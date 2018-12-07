/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
 */

var assert = require('assert-plus');
var aperture = require('aperture');
var errors = require('./errors.js');
var LRU = require('lru-cache');
var httpSignature = require('http-signature');
var restify = require('restify');
var sprintf = require('util').format;


///--- Globals

var ADMIN_ROLE_NAME = 'administrator';
var ANONYMOUS_USER = 'anonymous';



///--- API

/**
 * url: mahi server URL
 * typeTable: (optional) mahi type table for rule evaluation during
 *      authorization. Calls to authorize() will fail if the mahi client is not
 *      created with a type table and no type table is passed in to the request
 * maxAuthCacheSize: (optional) maximum number of objects to store in the
 *      client-side authentication cache. default 50
 * maxAuthCacheAgeMs: (optional) maximum age of objects in the client-side
 *      authentication cache. default 300000 (5 minutes)
 * maxTranslationCacheSize: (optional) maximum number of tranlations to store
 *      in the client-side translation cache. default 50
 * maxTranslationAgeMs: (optional) maximum age of translations in the
 *      client-side translation cache. default 300000 (5 minutes)
 */
function MahiClient(opts) {
    assert.object(opts, 'opts');
    assert.string(opts.url, 'url');
    assert.optionalObject(opts.agent, 'agent');
    assert.optionalObject(opts.typeTable, 'typeTable');
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
        url: opts.url,
        agent: opts.agent
    };

    if (opts.log) {
        clientOpts.log = opts.log;
    }
    self.http = restify.createJsonClient(clientOpts);
    if (opts.typeTable) {
        self.evaluator = aperture.createEvaluator({
            types: aperture.types,
            typeTable: opts.typeTable
        });
    }
}


MahiClient.prototype.close = function close() {
    var self = this;
    self.http.close();
    self.authCache.reset();
    self.translationCache.reset();
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


/**
 * Verifies that the signature is valid
 *
 * signature: signature object (e.g. req.authorization.signature from restify's
 *      authorizationParser)
 * keyId: keyId (e.g. "e3:4d:9b:26:bd:ef:a1:db:43:ae:4b:f7:bc:69:a7:24")
 * caller: caller received from mahi
 *
 * errors:
 * KeyDoesNotExistError
 * InvalidSignatureError
 */
MahiClient.prototype.verifySignature = function verifySignature(opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.signature, 'signature');
    assert.string(opts.keyId, 'keyId');
    assert.object(opts.caller, 'caller');

    var signature = opts.signature;
    var keyId = opts.keyId;
    var caller = opts.caller;

    var user = caller.user;
    var account = caller.account;
    var keys = user ? user.keys : account.keys;
    if (!keys || !keys[keyId]) {
        cb(new errors.KeyDoesNotExistError(keyId, account, user));
        return;
    }
    var key = keys[keyId];
    var ok = httpSignature.verifySignature(signature, key);

    if (!ok) {
        cb(new errors.InvalidSignatureError());
        return;
    }
    cb();
};


/**
 * Fetches account info given an account login.
 * Result looks like:
 *  {
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
 *      }
 *  }
 *
 *
 * account: account login
 * cb: callback in the form fn(err, obj)
 *
 * errors:
 * AccountDoesNotExistError
 * RedisError
 */
MahiClient.prototype.getAccount = function getAccount(account, cb) {
    assert.string(account, 'account');
    assert.func(cb, 'callback');

    var self = this;
    var fmt = '/accounts?login=%s';
    var path = sprintf(fmt, account);
    self._get(path, function gotAccount(err, info) {
        if (err) {
            cb(err);
            return;
        }

        self.translationCache.set('/uuid/' + info.account.uuid,
                info.account.login);
        self.translationCache.set('/account/' + info.account.login,
                info.account.uuid);

        cb(null, info);
    });
};


/**
 * see above
 *
 * arguments:
 * uuid: account uuid
 * cb: callback in the form fn(err, obj)
 *
 * errors:
 * AccountIdDoesNotExistError
 * RedisError
 */
MahiClient.prototype.getAccountById = function getAccountById(uuid, cb) {
    assert.uuid(uuid, 'uuid');
    assert.func(cb, 'callback');

    var self = this;
    var fmt = '/accounts/%s';
    var path = sprintf(fmt, uuid);
    self._get(path, function gotAccount(err, info) {
        if (err) {
            cb(err);
            return;
        }

        self.translationCache.set('/uuid/' + info.account.uuid,
                info.account.login);
        self.translationCache.set('/account/' + info.account.login,
                info.account.uuid);

        cb(null, info);
    });
};


/**
 * Fetches the given user under the specified account.
 * If `fallback` is set, no error will be returned if the user does not exist.
 * Instead, the account will be returned.
 *
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
 *
 * arguments:
 * user: user login
 * account: account login
 * fallback: (optional) whether to return the account even if user doesn't exist
 * cb: callback in the form fn(err, obj)
 *
 * errors:
 * UserDoesNotExistError unless fallback is true
 * AccountDoesNotExistError
 * RedisError
 */
MahiClient.prototype.getUser = function getUser(user, account, fallback, cb) {
    if (typeof (fallback) === 'function') {
        cb = fallback;
        fallback = false;
    }

    assert.string(user, 'user');
    assert.string(account, 'account');
    assert.bool(fallback, 'fallback');
    assert.func(cb, 'callback');

    var self = this;
    var fmt = '/users?account=%s&login=%s&fallback=%s';
    var path = sprintf(fmt, account, user, fallback);
    self._get(path, function gotUser(err, info) {
        if (err) {
            cb(err);
            return;
        }

        self.translationCache.set('/uuid/' + info.account.uuid,
                info.account.login);
        self.translationCache.set('/account/' + info.account.login,
                info.account.uuid);

        if (info.user) {
            self.translationCache.set('/uuid/' + info.user.uuid,
                    info.user.login);
            self.translationCache.set('/user/' + info.user.login,
                    info.user.uuid);
        }

        cb(null, info);
    });
};

/**
 * see above
 *
 * arguments:
 * uuid: user uuid
 * cb: callback in the form fn(err, obj)
 *
 * errors:
 * UserIdDoesNotExistError unless fallback is true
 * RedisError
 */
MahiClient.prototype.getUserById = function getUserById(uuid, cb) {
    assert.uuid(uuid, 'uuid');
    assert.func(cb, 'callback');

    var self = this;
    var fmt = '/users/%s';
    var path = sprintf(fmt, uuid);
    self._get(path, cb);
    self._get(path, function gotUser(err, info) {
        if (err) {
            cb(err);
            return;
        }

        self.translationCache.set('/uuid/' + info.account.uuid,
                info.account.login);
        self.translationCache.set('/account/' + info.account.login,
                info.account.uuid);

        self.translationCache.set('/uuid/' + info.user.uuid, info.user.login);
        self.translationCache.set('/user/' + info.user.login, info.user.uuid);

        cb(null, info);
    });
};


/**
 * typeTable: type lookup table used for rule evaluation. Required if type table
 *      was not passed in when the client was created.
 * principal: the request caller in the format
 *      {account: {...}, roles: {...}} or
 *      {account: {...}, user: {...}, roles: {...}}
 *      from getAccount, getAccountById, getUser, getUserById or fetchAuthInfo
 * action: auth action
 * resource.roles: array of role tag UUIDS
 * resource.owner: the resource owner in the format
 *      {account: {...}, roles: {...}} or
 *      {account: {...}, user: {...}, roles: {...}}
 *      from getAccount, getAccountById, getUser, getUserById or fetchAuthInfo
 * conditions: all additional context collected as part of the request,
 *      including activeRoles
 *
 * throws AccountBlockedError if the principal or resource owner is not
 *     approved for provisioning
 * throws CrossAccountError if the principal is an account owner and is
 *     making a request to a non-public resource in a different account
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
    if (!self.evaluator) {
        assert.object(opts.typeTable, 'opts.typeTable');
    }
    var evaluator = opts.typeTable ? aperture.createEvaluator({
        types: aperture.types,
        typeTable: opts.typeTable
    }) : self.evaluator;

    var principal = opts.principal;
    var resource = opts.resource;

    var resourceTags = resource.roles;
    var owner = resource.owner;
    var activeRoles = opts.conditions.activeRoles;

    /* The final context we will give to aperture. */
    var context = {
        action: opts.action,
        conditions: opts.conditions,
        resource: ''
    };
    /*
     * The set of rules we will select from all the relevant policy and
     * pass to aperture for evaluation.
     */
    var rulesToEvaluate = [];
    /*
     * List of roles that we selected rules from. We track this in order
     * to return the correct error code (no roles were used vs. roles were
     * used but they had no rules on them).
     */
    var matchingRoles = [];

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
     * Deny if the caller or owner is not approved for provisioning (unless
     * either caller is an operator or the owner is an operator and it's only
     * the owner that isn't approved).
     */
    if (!principal.account.approved_for_provisioning &&
        !principal.account.isOperator) {
        throw new errors.AccountBlockedError(principal.account.login);
    }
    if (!resource.owner.account.approved_for_provisioning &&
        !resource.owner.account.isOperator &&
        !principal.account.isOperator) {
        throw new errors.AccountBlockedError(resource.owner.account.login);
    }

    /*
     * Mahi mainly uses the "action" and "conditions" parts of the aperture
     * language -- we enforce "principal" constraints by limiting the list of
     * roles we consider here based on membership, and "resource" constraints
     * in one of two ways: by using the resource role tags (stored with the
     * resource itself); or by using the regular resource evaluator only if
     * the "resource" part of the rule was explicitly set to '*' or 'all'.
     */
    for (i = 0; i < activeRoles.length; ++i) {
        // check if the principal is allowed to assume the role
        var role = principal.roles[activeRoles[i]];
        if (!role) {
            throw new errors.InvalidRoleError(activeRoles[i]);
        }

        /*
         * Aperture parser sets .resources to the Number 1 if '*' or 'all' was
         * given as the target.
         */
        var rulesWithAll = role.rules.filter(function (rule) {
            return (rule[1].resources === 1);
        });

        /*
         * Having the "administrator" role on a given account means you can do
         * anything to objects owned by that account.
         */
        if (role.name === ADMIN_ROLE_NAME) {
            if (owner.account.uuid === role.account) {
                return (true);
            }
            /*
             * Sub-users on an operator account that have been added to that
             * operator's "administrator" rule inherit operator access.
             *
             * We have to check the account is the same as the role here so that
             * being on the admin role of a *different* account doesn't confer
             * operator access.
             */
            if (principal.account.isOperator &&
                principal.account.uuid === role.account) {
                return (true);
            }
            /*
             * Otherwise ignore this role membership -- admin roles can't have
             * any attached policy.
             */

        } else if (resourceTags.indexOf(activeRoles[i]) >= 0) {
            /* Ordinary non-admin roles are processed below. */
            matchingRoles.push(activeRoles[i]);
            role.rules.forEach(function (rule) {
                rulesToEvaluate.push(rule[1]);
            });

        } else if (rulesWithAll.length > 0) {
            matchingRoles.push(activeRoles[i]);
            /*
             * Only push the rules that have the * resource. If we push any
             * others, they will end up applying even though there's no role
             * tag!
             */
            rulesWithAll.forEach(function (rule) {
                rulesToEvaluate.push(rule[1]);
            });
        }
    }

    if (!matchingRoles.length) {
        throw new errors.NoMatchingRoleTagError();
    }

    if (!rulesToEvaluate.length) {
        throw new errors.RulesEvaluationFailedError();
    }

    var ok = evaluator.evaluate(rulesToEvaluate, context);
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

    var uncached = [];
    var translations = {};

    opts.uuids.forEach(function (uuid) {
        var path = sprintf('/uuid/%s', uuid);
        var cached = self.translationCache.get(path);
        if (!cached) {
            uncached.push(uuid);
        } else {
            translations[uuid] = cached;
        }
    });

    // All uuids were found in the cache. Nothing to ask the server.
    if (!uncached.length) {
        setImmediate(function () {
            cb(null, translations);
        });
        return;
    }

    var q = '?&uuid=' + uncached.join('&uuid=');

    self.http.get('/names' + q, function (err, req, res, obj) {
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


/**
 *
 * account: account login
 * type (optional): type of the names. valid values: role, user, policy
 * names (optional): array of role/user/policy names to translate
 * returns:
 *
 * { "account": <accountUuid> }
 *
 * or
 *
 * {
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

    var uncached = [];
    var translations = {};

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
    } else {
        translations.uuids = {};
    }

    names.forEach(function (name) {
        var path = sprintf('/%s/%s/%s', type, account, name);
        var cached = self.translationCache.get(path);
        if (!cached) {
            uncached.push(name);
        } else {
            translations.uuids[name] = cached;
        }
    });

    // All names/logins were found in the cache. Nothing to ask the server.
    if (translations.account && !uncached.length) {
        setImmediate(function () {
            cb(null, translations);
        });
        return;
    }

    var q = sprintf('?account=%s&type=%s', account, type);
    if (uncached.length) {
        q += '&name=' + uncached.join('&name=');
    }

    self.http.get('/uuids' + q, function (err, req, res, obj) {
        if (err) {
            cb(err);
            return;
        }
        self.translationCache.set(sprintf('/account/%s', account), obj.account);
        translations.account = obj.account;
        if (obj.uuids) {
            Object.keys(obj.uuids).forEach(function (name) {
                var path = sprintf('/%s/%s/%s', type, account, name);
                self.translationCache.set(path, obj.uuids[name]);
                translations.uuids[name] = obj.uuids[name];
            });
        }
        cb(null, translations);
    });
};


MahiClient.prototype.getLookup = function getLookup(opts, cb) {
    if (typeof (opts === 'function')) {
        cb = opts;
        opts = {};
    }
    assert.object(opts, 'opts');
    assert.func(cb, 'callback');

    var self = this;

    self.http.get('/lookup', function (err, req, res, obj) {
        if (err) {
            cb(err);
            return;
        }
        cb(null, obj);
    });
};



module.exports = {
    MahiClient: MahiClient,
    createClient: function (opts) {
        return (new MahiClient(opts));
    },
    ANONYMOUS_USER: ANONYMOUS_USER,
    ADMIN_ROLE: ADMIN_ROLE_NAME
};
