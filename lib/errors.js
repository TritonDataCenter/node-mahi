// Copyright 2014 Joyent, Inc.  All rights reserved.

var util = require('util');
var sprintf = util.format;
var WError = require('verror').WError;

function MahiError(cause, message) {
    var off = 0;
    if (cause instanceof Error) {
        off = 1;
    }

    var args = Array.prototype.slice.call(arguments, off);
    args.unshift({
        cause: off ? cause : undefined,
        constructorOpt: MahiError
    });
    WError.apply(this, args);
}
util.inherits(MahiError, WError);
MahiError.prototype.name = 'MahiError';

function KeyDoesNotExistError(keyId, account, user) {
    var path = user ? sprintf('/%s/%s/keys/%s', account, user, keyId) :
                      sprintf('/%s/keys/%s', account, keyId);
    MahiError.call(this, path + ' does not exist');
}
util.inherits(KeyDoesNotExistError, MahiError);

function InvalidSignatureError() {
    MahiError.call(this, 'The signature we calculated does not match the one ' +
        'you sent.');
}
util.inherits(InvalidSignatureError, MahiError);

function RoleTagMismatchError() {
    MahiError.call(this, 'None of your active roles give access ' +
        'to this resource.');
}
util.inherits(RoleTagMismatchError, MahiError);

module.exports = {
    KeyDoesNotExistError: KeyDoesNotExistError,
    InvalidSignatureError: InvalidSignatureError,
    RoleTagMismatchError: RoleTagMismatchError
};
