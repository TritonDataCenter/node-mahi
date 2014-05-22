// Copyright (c) 2014 Joyent, Inc.  All rights reserved.

var assert = require('assert-plus');
var aperture = require('aperture');
var errors = require('./errors.js');
var LRU = require('lru-cache');
var httpSignature = require('http-signature');
var restify = require('restify');
var sprintf = require('util').format;


///--- Globals

var ADMIN_ROLE_NAME = 'administrator';



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
        /*
         * If UserDoesNotExist, we still want to return account info if it's
         * needed. This is used when loading the resource owner. We look up the
         * "anonymous" user for the owner account since mahi has to look up
         * account info anyway, but we still want the account information if
         * the anonymous user does not exist.
         */
        if (err && err.restCode === 'UserDoesNotExist') {
            cb(err, obj.info);
            return;
        } else if (err) {
            cb(err, obj);
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
 * user: user login
 * account: account login
 * returns same object as authenticate()
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


/*
 * principal: the object recevied from authenticate
 * action: auth action
 * resource.roles: array of role tag UUIDS
 * resource.owner: the object received from calling mahi.getAccount with the
 *      resource owner's login
 * conditions: all additional context collected as part of the request,
 *      including activeRoles
 *
 * throws AccountBlockedError if the principal or resource owner is not
 *     approved for provisioning
 * throws NoMatchingRoleTagError if no active roles match resource role tags
 * throws InvalidRoleError if activeRoles contains a role that the principal
 *      cannot assume
 * throws RulesEvaluationFailedError if no rules pass Aperture evaluation or
 *      if there are no rules to evaluate
 *
 * returns true if authorization is successful
 */
MahiClient.prototype.authorize = function authorize(opts) {
    assert.object(opts, 'opts');
    assert.object(opts.principal, 'opts.principal');
    assert.object(opts.principal.roles, 'opts.principal.roles');
    assert.object(opts.principal.account, 'opts.principal.account');
    assert.optionalObject(opts.principal.user, 'opts.principal.user');
    assert.string(opts.action, 'opts.action');
    assert.object(opts.resource, 'opts.resource');
    assert.arrayOfString(opts.resource.roles, 'opts.resource.roles');
    assert.object(opts.resource.owner, 'opts.resource.owner');
    assert.string(opts.resource.owner.account.uuid,
            'opts.resource.owner.account.uuid');
    assert.object(opts.conditions, 'opts.conditions');
    assert.arrayOfString(opts.conditions.activeRoles,
            'opts.conditions.activeRoles');

    var self = this;

    var principal = opts.principal;
    var resource = opts.resource;

    var resourceTags = resource.roles;
    var owner = resource.owner;
    var activeRoles = opts.conditions.activeRoles;
    var context = {
        action: opts.action,
        conditions: opts.conditions
    };
    var rules = [];
    var roles = [];
    var i;

    /*
     * If the caller is the account owner, allow access to all of the account's
     * stuff. If the caller is an operator, allow access. Only do these checks
     * if the caller is acting as an account owner (not a user).
     */
    if (!principal.user) {
        if (owner.account.uuid === principal.account.uuid ||
            principal.account.isOperator) {

            return (true);
        }
    }

    /*
     * Deny if the caller or owner is not approved for provisioning.
     * Operators will have been allowed access above regardless of approved
     * for provisioning status on their account or the owner of the resource.
     */
    if (!principal.account.approved_for_provisioning) {
        throw new errors.AccountBlockedError(principal.account.login);
    }
    if (!resource.owner.account.approved_for_provisioning) {
        throw new errors.AccountBlockedError(resource.owner.account.login);
    }

    /*
     * Mahi only uses the "action" and "conditions" parts of the aperture
     * language. We enforce "principal" and "resource" checks by comparing the
     * resource role tags with the roles the user has active and is allowed to
     * access.
     */
    for (i = 0; i < activeRoles.length; ++i) {
        // check if the principal is allowed to assume the role
        if (!principal.roles[activeRoles[i]]) {
            throw new errors.InvalidRoleError(activeRoles[i]);
        }

        /*
         * The isOperator check here means that admin users "inherit" operator
         * privileges from the account.
         */
        if (principal.roles[activeRoles[i]].name === ADMIN_ROLE_NAME) {
            if (owner.account.uuid === principal.account.uuid ||
                principal.account.isOperator) {

                return (true);
            }
        } else if (resourceTags.indexOf(activeRoles[i]) >= 0) {
                roles.push(activeRoles[i]);
        }
    }

    if (!roles.length) {
        throw new errors.NoMatchingRoleTagError();
    }

    roles.forEach(function (role) {
        principal.roles[role].rules.forEach(function (rule) {
            rules.push(rule[1]);
        });
    });

    if (!rules.length) {
        throw new errors.RulesEvaluationFailedError();
    }

    var ok = self.evaluator.evaluate(rules, context);
    if (!ok) {
        throw new errors.RulesEvaluationFailedError();
    }
    return (ok);
};


/*
 * uuids: array of uuids
 * returns a mapping of {uuid: name}
 */
MahiClient.prototype.getName = function getName(opts, cb) {
    assert.object(opts, 'opts');
    assert.arrayOfString(opts.uuids, 'opts.uuids');

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


/*
 * account: account login
 * type (optional): type of the names. valid values: role, user, policy
 * names (optional): array of role/user/policy names to translate
 * returns: {
 *      "account": <accountUuid>,
 *      "uuids": {
 *          <name>: <uuid>
 *      }
 * }
 */
MahiClient.prototype.getUuid = function getUuid(opts, cb) {
    assert.object(opts, 'opts');
    assert.string(opts.account, 'opts.account');
    if (opts.type || opts.names) {
        assert.string(opts.type, 'opts.type');
        assert.arrayOfString(opts.names, 'opts.names');
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
    if (translations.account && !params.names.length) {
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
