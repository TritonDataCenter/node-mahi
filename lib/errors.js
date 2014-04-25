// Copyright 2014 Joyent, Inc.  All rights reserved.

var restify = require('restify');
var util = require('util');

var sprintf = util.format;
var RestError = restify.RestError;

function MahiError(obj) {
    obj.contructorOpts = this.contructor;
    RestError.call(this, obj);
}
util.inherits(MahiError, RestError);
MahiError.prototype.name = 'MahiError';

function KeyDoesNotExistError(keyId, account, user) {
    var path = user ? sprintf('/%s/%s/keys/%s', account, user, keyId) :
                      sprintf('/%s/keys/%s', account, keyId);
    MahiError.call(this, {
        restCode: 'KeyDoesNotExist',
        statusCode: 404,
        message: path + ' does not exist'
    });
}
util.inherits(KeyDoesNotExistError, MahiError);

function InvalidSignatureError() {
    MahiError.call(this, {
        restCode: 'InvalidSignature',
        statusCode: 403,
        message: 'The signature we calculated does not match the one ' +
            'you sent'
    });
}
util.inherits(InvalidSignatureError, MahiError);

function RoleTagMismatchError() {
    MahiError.call(this, {
        restCode: 'RoleTagMismatch',
        statusCode: 403,
        message: 'None of your active roles give access to this resource.'
    });
}
util.inherits(RoleTagMismatchError, MahiError);

module.exports = {
    KeyDoesNotExistError: KeyDoesNotExistError,
    InvalidSignatureError: InvalidSignatureError,
    RoleTagMismatchError: RoleTagMismatchError
};
