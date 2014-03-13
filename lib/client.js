// Copyright (c) 2014 Joyent, Inc.  All rights reserved.

var assert = require('assert-plus');
var aperture = require('aperture');
var errors = require('./errors.js');
var LRU = require('lru-cache');
var httpSignature = require('http-signature');
var restify = require('restify');
var sprintf = require('util').format;


///--- API

function MahiClient(opts) {
    assert.object(opts, 'opts');
    assert.string(opts.url, 'url');
    assert.object(opts.typeTable, 'typeTable');
    assert.optionalNumber(opts.maxAuthCacheSize, 'maxAuthCacheSize');
    assert.optionalNumber(opts.maxAuthCacheAgeMs, 'maxAuthCacheAgeMs');
    assert.optionalNumber(opts.maxAuthCacheSize, 'maxTranslationCacheSize');
    assert.optionalNumber(opts.maxAuthCacheAgeMs, 'maxTranslationCacheAgeMs');

    var self = this;

    // cache for user and account info blobs
    self.authCache = new LRU({
        max: opts.maxAuthCacheSize || 50,
        maxAge: opts.maxAuthCacheAgeMs || 1000 * 60 * 5
    });

    // cache for uuid->name and name->uuid translations
    self.translationCache = new LRU({
        max: opts.maxTranslationCacheSize || 50,
        maxAge: opts.maxTranslationCacheAgeMs || 1000 * 60 * 5
    });

    self.http = restify.createJsonClient({url: opts.url});
    self.evaluator = aperture.createEvaluator({
        types: aperture.types,
        typeTable: opts.typeTable
    });
}


MahiClient.prototype.close = function close() {
    var self = this;
    self.http.close();
};


MahiClient.prototype.get = function get(path, cb) {
    var self = this;
    var cached = self.authCache.get(path);
    if (cached) {
        setImmediate(function () {
            cb(null, cached);
            return;
        });
        return;
    }

    self.http.get(path, function (err, req, res, obj) {
        if (err) {
            cb(err);
            return;
        }
        self.authCache.set(path, obj);
        cb(null, obj);
    });
};


/*
 * returns an object like
 * {
 *      roles: {
 *          <uuid>: {
 *              name: <name>
 *              uuid: <roleUUID>,
 *              type: "role",
 *              account: <accountUUID>,
 *              policies: [ <policyUUIDs> ]
 *              rules: [ < [text, parsed] pairs> ]
 *          }, ...
 *      },
 *      account: {
 *          type: "account",
 *          uuid: <accountUUID>,
 *          login: <accountLogin>,
 *          approved_for_provisioning: true/false,
 *          keys: {
 *              <keyId>: <key>, ...
 *          },
 *          groups: {
 *              <groupname>: true, ...
 *          },
 *          isOperator: true/false
 *      },
 *      user: {
 *          type: "user",
 *          uuid: <userUUID>,
 *          account: <accountUUID>,
 *          login: <userLogin>
 *          keys: {
 *              <keyId>: <key>, ...
 *          },
 *          roles: [ <roleUUIDs> ]
 *      }
 * }
 *
 */
MahiClient.prototype.authenticate = function authenticate(opts, cb) {
    assert.object(opts, 'opts');
    assert.string(opts.account, 'account');
    assert.string(opts.keyId, 'keyId');
    assert.optionalObject(opts.signature, 'signature');
    assert.optionalString(opts.user, 'user');
    assert.func(cb, 'callback');

    var self = this;

    var account = opts.account;
    var keyId = opts.keyId;
    var signature = opts.signature;
    var user = opts.user;

    var path = user ? sprintf('/user/%s/%s', account, user) :
                      sprintf('/account/%s',  account);

    self.get(path, function gotInfo(err, info) {
        if (err) {
            cb(err);
            return;
        }
        var keys = info.user ? info.user.keys : info.account.keys;
        if (!keys || !keys[keyId]) {
            cb(new errors.KeyDoesNotExistError(keyId, account, user));
            return;
        }
        var key = keys[keyId];
        var ok = signature ?
            httpSignature.verifySignature(signature, key) :
            true;

        if (!ok) {
            cb(new errors.InvalidSignatureError());
            return;
        }

        cb(null, info);
        return;
    });
};


MahiClient.prototype.authorize = function authorize(opts) {
    assert.object(opts, 'opts');
    assert.arrayOfString(opts.activeRoles, 'activeRoles'); // names
    assert.arrayOfString(opts.resourceTags, 'resourceTags'); // uuids
    assert.object(opts.context, 'context');
    assert.object(opts.info, 'info');

    var self = this;

    var activeRoles = opts.activeRoles;
    var resourceTags = opts.resourceTags;
    var context = opts.context;
    var info = opts.info;
    var rules = [];

    resourceTags.forEach(function (tag) {
        if (!info.roles[tag]) {
            // none of the user's roles match any of the tags on the resource
            throw new errors.RoleTagMismatchError();
        }
        // at this point we know that the user has a role that matches the tag
        // but we do not know if that role is active for this request
        var name = info.roles[tag].name;
        if (activeRoles.indexOf(name) < 0) {
            throw new errors.InactiveRoleError();
        }
        info.roles[tag].rules.forEach(function (rule) {
            rules.push(rule[1]);
        });
    });

    return (self.evaluator.evaluate(rules, context));
};


MahiClient.prototype.getName = function getName(opts, cb) {
    assert.object(opts);
    assert.arrayOfString(opts.uuids);

    var self = this;

    var params = {
        uuids: []
    };
    var translations = {};

    opts.uuids.forEach(function (uuid) {
        var path = sprintf('/uuid/%s', uuid);
        var cached = self.translationCache.get(path);
        if (!cached) {
            params.uuids.push(uuid);
        } else {
            translations[uuid] = cached;
        }
    });

    self.http.post('/getName', params, function (err, req, res, obj) {
        if (err) {
            cb(err);
            return;
        }
        Object.keys(obj).forEach(function (uuid) {
            self.translationCache.set(sprintf('/uuid/%s', uuid), obj[uuid]);
            translations[uuid] = obj[uuid];
        });
        cb(null, translations);
    });
};


MahiClient.prototype.getUuid = function getUuid(opts, cb) {
    assert.object(opts);
    assert.string(opts.account);
    if (opts.type || opts.names) {
        assert.string(opts.type);
        assert.arrayOfString(opts.names);
    }

    var self = this;
    var account = opts.account;
    var type = opts.type;
    var names = opts.names || [];

    var params = {
        account: account,
        type: type,
        names: []
    };
    var translations = {
        uuids: {}
    };

    names.forEach(function (name) {
        var path = sprintf('/%s/%s/%s', type, account, name);
        var cached = self.translationCache.get(path);
        if (!cached) {
            params.names.push(name);
        } else {
            translations.uuids[name] = cached;
        }
    });

    self.http.post('/getUuid', params, function (err, req, res, obj) {
        if (err) {
            cb(err);
            return;
        }
        self.translationCache.set(sprintf('/account/%s', account), obj.account);
        translations.account = obj.account;
        Object.keys(obj.uuids).forEach(function (name) {
            var path = sprintf('/%s/%s/%s', type, account, name);
            self.translationCache.set(path, obj[name]);
            translations.uuids[name] = obj.uuids[name];
        });
        cb(null, translations);
    });
};


module.exports = {
    MahiClient: MahiClient,
    createClient: function (opts) {
        return (new MahiClient(opts));
    }
};


///--- Tests

function test() {
    var client = new MahiClient({
        url: 'http://localhost:8080',
        typeTable: {
            ip: 'ip'
        }
    });

    client.authenticate({
        account: 'jjelinek',
        user: 'subuser3',
        keyId: '7b:a4:7c:6c:c7:2f:d9:a6:bd:ec:1b:2f:e8:3d:40:18'
    }, function (err, res) {
        if (err) {
            console.log(err);
            process.exit(1);
        }
        console.log(JSON.stringify(res, null, 2));
        var ok = client.authorize({
            activeRoles: ['devread'],
            resourceTags: ['5d0049f4-67b3-11e3-8059-273f883b3fb6'],
            context: {
                'action': 'read',
                'resource': 'red',
                'conditions': {
                    'ip': '10.0.0.1'
                }
            },
            info: res
        });
        console.log(ok);
        client.close();
    });
}

if (require.main === module) {
    test();
}
