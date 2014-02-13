// Copyright (c) 2014 Joyent, Inc.  All rights reserved.

var assert = require('assert-plus');
var aperture = require('aperture');
var errors = require('./errors.js');
var LRU = require('lru-cache');
var httpSignature = require('http-signature');
var restify = require('restify');
var sprintf = require('util').format;

function MahiClient(opts) {
    var self = this;
    self.cache = new LRU({
        max: opts.maxCacheSize || 50,
        maxAge: opts.maxCacheAgeMs || 1000 * 60 * 5
    });
    self.http = restify.createJsonClient({url: opts.url});
    self.evaluator = aperture.createEvaluator({
        types: {ip: 'ip'}
    });
}


MahiClient.prototype.get = function get(path, cb) {
    var self = this;
    var cached = self.cache.get(path);
    if (cached) {
        // async functions should be consistently async
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
        self.cache.set(path, obj);
        cb(null, obj);
        return;
    });
};

MahiClient.prototype.close = function close() {
    var self = this;
    self.http.close();
};


MahiClient.prototype.authenticate = function authenticate(opts, cb) {
    assert.object(opts, 'opts');
    assert.string(opts.account, 'account');
    assert.string(opts.keyId, 'keyId');
    assert.object(opts.signature, 'signature');
    assert.optionalString(opts.user, 'user');
    assert.func(cb, 'callback');

    var self = this;

    var account = opts.account;
    var keyId = opts.keyId;
    var signature = opts.signature;
    var user = opts.user;

    var path = user ? sprintf('/info/%s/%s', account, user) :
                      sprintf('/info/%s',  account);

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
        var ok = httpSignature.verifySignature(signature, key);
        if (!ok) {
            cb(new errors.InvalidSignatureError());
            return;
        }
        console.log(info);
        cb(null, info);
        return;
    });
};


MahiClient.prototype.authorize = function authorize(opts) {
    assert.object(opts, 'opts');
    assert.arrayOfString(opts.activeRoles, 'activeRoles');
    assert.object(opts.context, 'context');
    assert.object(opts.info, 'info');

    var self = this;

    var activeRoles = opts.activeRoles;
    var context = opts.context;
    var info = opts.info;
    var policies = [];

    activeRoles.forEach(function (role) {
        info.roles[role].policies.forEach(function (policy) {
            policies.push(policy);
        });
    });
    console.log(policies);

    return (self.evaluator.evaluate(context, policies));
};


module.exports = {
    MahiClient: MahiClient
};
