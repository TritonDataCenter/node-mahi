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
    assert.optionalNumber(opts.maxTranslationCacheSize,
        'maxTranslationCacheSize');
    assert.optionalNumber(opts.maxTranslationCacheAgeMs,
        'maxTranslationCacheAgeMs');

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

    var clientOpts = {
        url: opts.url
    };

    if (opts.log) {
        clientOpts.log = opts.log;
    }
    self.http = restify.createJsonClient(clientOpts);
    self.evaluator = aperture.createEvaluator({
        types: aperture.types,
        typeTable: opts.typeTable
    });
}


MahiClient.prototype.close = function close() {
    var self = this;
    self.http.close();
};


MahiClient.prototype._get = function _get(path, cb) {
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

    self._get(path, function gotInfo(err, info) {
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


/*
 * account: account login
 */
MahiClient.prototype.getAccount = function getAccount(account, cb) {
    assert.string(account);
    assert.func(cb);

    var self = this;
    var fmt = '/account/%s';
    var path = sprintf(fmt, account);
    self._get(path, cb);
};


/*
 * account: account login
 * user: user login
 */
MahiClient.prototype.getUser = function getUser(user, account, cb) {
    assert.string(user);
    assert.string(account);
    assert.func(cb);

    var self = this;
    var fmt = '/user/%s/%s';
    var path = sprintf(fmt, account, user);
    self._get(path, cb);
};


MahiClient.prototype.authorize = function authorize(opts) {
    assert.object(opts, 'opts');
    assert.object(opts.principal);
    assert.object(opts.principal.roles);
    assert.string(opts.action);
    assert.object(opts.resource);
    assert.arrayOfString(opts.resource.roles);
    assert.object(opts.conditions);
    assert.arrayOfString(opts.conditions.activeRoles);

    var self = this;

    var principal = opts.principal;
    var resourceTags = opts.resource.roles;
    var activeRoles = opts.conditions.activeRoles;
    var context = {
        action: opts.action,
        conditions: opts.conditions
    };
    var rules = [];
    var roles = [];

    /*
     * Mahi only uses the "action" and "conditions" parts of the aperture
     * language. We enforce "principal" and "resource" checks by comparing the
     * resource role tags with the roles the user has active and is allowed to
     * access.
     */
    resourceTags.forEach(function (tag) {
        if (principal.roles[tag] && activeRoles.indexOf(tag) >= 0) {
            roles.push(tag);
        }
    });

    if (!roles.length) {
        throw new errors.RoleTagMismatchError();
    }

    roles.forEach(function (role) {
        principal.roles[role].rules.forEach(function (rule) {
            rules.push(rule[1]);
        });
    });

    if (!rules.length) {
        return (false);
    }

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

    // All uuids were found in the cache. Nothing to ask the server.
    if (!params.uuids.length) {
        setImmediate(function () {
            cb(null, translations);
        });
        return;
    }

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

    /*
     * If no type was passed in, assume that we only want to look up the uuid
     * for the account, so check if we have the translation cached. The account
     * login is translated server side regardless of whether there are other
     * things we want to translate. This saves us the round trip if we are only
     * translating the account login AND we have the translation cached.
     */
    if (!type) {
        var accountInfo =
            self.translationCache.get(sprintf('/account/%s', account));
        if (accountInfo) {
            translations.account = accountInfo;
            setImmediate(function () {
                cb(null, translations);
            });
            return;
        }
    }

    names.forEach(function (name) {
        var path = sprintf('/%s/%s/%s', type, account, name);
        var cached = self.translationCache.get(path);
        if (!cached) {
            params.names.push(name);
        } else {
            translations.uuids[name] = cached;
        }
    });

    // All names/logins were found in the cache. Nothing to ask the server.
    if (!params.names.length) {
        setImmediate(function () {
            cb(null, translations);
        });
        return;
    }

    self.http.post('/getUuid', params, function (err, req, res, obj) {
        if (err) {
            cb(err);
            return;
        }
        self.translationCache.set(sprintf('/account/%s', account), obj.account);
        translations.account = obj.account;
        Object.keys(obj.uuids).forEach(function (name) {
            var path = sprintf('/%s/%s/%s', type, account, name);
            self.translationCache.set(path, obj.uuids[name]);
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
        client.close();
    });
}

if (require.main === module) {
    test();
}
