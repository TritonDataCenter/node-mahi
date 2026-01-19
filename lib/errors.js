/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
 * Copyright 2025 Edgecast Cloud LLC.
 */

var util = require('util');
var RestError = require('restify').RestError;

var sprintf = util.format;

function MahiError(obj) {
    obj.constructorOpt = this.constructor;
    RestError.call(this, obj);
}
util.inherits(MahiError, RestError);
MahiError.prototype.name = 'MahiError';

function AccessKeyNotFoundError(accessKeyId) {
    MahiError.call(this, {
        restCode: 'AccessKeyNotFound',
        statusCode: 404,
        message: 'Access key ' + accessKeyId + ' does not exist'
    });
}
util.inherits(AccessKeyNotFoundError, MahiError);
AccessKeyNotFoundError.prototype.name = 'AccessKeyNotFoundError';


function AccountBlockedError(account) {
    MahiError.call(this, {
        restCode: 'AccountBlocked',
        statusCode: 403,
        message: 'Account ' + account + ' is blocked.'
    });
}
util.inherits(AccountBlockedError, MahiError);
AccountBlockedError.prototype.name = 'AccountBlockedError';


function CrossAccountError() {
    MahiError.call(this, {
        restCode: 'CrossAccount',
        statusCode: 403
    });
}
util.inherits(CrossAccountError, MahiError);
CrossAccountError.prototype.name = 'CrossAccountError';


function InvalidRoleError(r) {
    MahiError.call(this, {
        restCode: 'InvalidRole',
        statusCode: 403,
        message: r
    });
}
util.inherits(InvalidRoleError, MahiError);
InvalidRoleError.prototype.name = 'InvalidRoleError';


function InvalidSignatureError() {
    MahiError.call(this, {
        restCode: 'InvalidSignature',
        statusCode: 403,
        message: 'The signature we calculated does not match the one ' +
            'you sent'
    });
}
util.inherits(InvalidSignatureError, MahiError);
InvalidSignatureError.prototype.name = 'InvalidSignatureError';


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
KeyDoesNotExistError.prototype.name = 'KeyDoesNotExistError';


function NoMatchingRoleTagError() {
    MahiError.call(this, {
        restCode: 'NoMatchingRoleTag',
        statusCode: 403,
        message: 'None of your active roles are present on the resource.'
    });
}
util.inherits(NoMatchingRoleTagError, MahiError);
NoMatchingRoleTagError.prototype.name = 'NoMatchingRoleTagError';


function RulesEvaluationFailedError() {
    MahiError.call(this, {
        restCode: 'RulesEvaluationFailed',
        statusCode: 403,
        message: 'No rules allowed access'
    });
}
util.inherits(RulesEvaluationFailedError, MahiError);
RulesEvaluationFailedError.prototype.name = 'RulesEvaluationFailedError';


function RequestTimeTooSkewedError() {
    MahiError.call(this, {
        restCode: 'RequestTimeTooSkewed',
        statusCode: 403,
        message: 'The difference between the request time and the server' +
        'time is too large'
    });
}
util.inherits(RequestTimeTooSkewedError, MahiError);
RequestTimeTooSkewedError.prototype.name = 'RequestTimeTooSkewedError';


module.exports = {
    AccessKeyNotFoundError: AccessKeyNotFoundError,
    AccountBlockedError: AccountBlockedError,
    CrossAccountError: CrossAccountError,
    InvalidRoleError: InvalidRoleError,
    InvalidSignatureError: InvalidSignatureError,
    KeyDoesNotExistError: KeyDoesNotExistError,
    MahiError: MahiError,
    NoMatchingRoleTagError: NoMatchingRoleTagError,
    RequestTimeTooSkewedError: RequestTimeTooSkewedError,
    RulesEvaluationFailedError: RulesEvaluationFailedError
};
