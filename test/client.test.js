/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
 */

//
// To test: point this at an existing mahi server that has been bootstrapped
// with the test-nodeletes test data under the test/data directory of mahi.git

var mahi = require('..');
var test = require('tap').test;

var CLIENT;
function setup() {
    test('setup', function (t) {
        CLIENT = mahi.createClient({
            url: process.env.MAHI_TEST_URL || 'http://127.0.0.1:8080',
            typeTable: {
                'ip': 'ip'
            }
        });

        t.end();
    });
}

function teardown() {
    test('teardown', function (t) {
        CLIENT.close();
        t.end();
    });
}

setup(test); test('getAccount', function (t) {
    CLIENT.getAccount('banks', function (err, info) {
        t.notOk(err, 'err');
        t.ok(info, 'info');
        t.ok(info.account, 'info.account');
        t.end();
    });
}); teardown(test);

setup(test); test('getUser', function (t) {
    CLIENT.getUser('bankofamerica', 'banks', function (err, info) {
        t.notOk(err, 'err');
        t.ok(info, 'info');
        t.ok(info.account, 'info.account');
        t.ok(info.user, 'info.user');
        t.end();
    });
}); teardown(test);

setup(test); test('getAccountById', function (t) {
    CLIENT.getAccountById('bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f',
            function (err, info) {
        t.notOk(err, 'err');
        t.ok(info, 'info');
        t.ok(info.account, 'info.account');
        t.end();
    });
}); teardown(test);

setup(test); test('getUserById', function (t) {
    CLIENT.getUserById('3ffc7b4c-66a6-11e3-af09-8752d24e4669',
            function (err, info) {
        t.notOk(err, 'err');
        t.ok(info, 'info');
        t.ok(info, 'info');
        t.ok(info.account, 'info.account');
        t.ok(info.user, 'info.user');
        t.end();
    });
}); teardown(test);


setup(test); test('getName', function (t) {
    var uuids = [
        'bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f',
        '1e77f528-9e64-11e3-8d12-838d40383bce',
        '2a05359a-9e64-11e3-816d-e7f87365cf40'
    ];
    CLIENT.getName({
        uuids: uuids
    }, function (err, lookup) {
        uuids.forEach(function (uuid) {
            t.ok(lookup[uuid], 'got ' + uuid);
        });
        t.end();
    });
}); teardown(test);

setup(test); test('getUuid - account only', function (t) {
    CLIENT.getUuid({
        account: 'banks'
    }, function (err, lookup) {
        t.ok(lookup.account);
        t.end();
    });
}); teardown(test);

setup(test); test('getUuid - roles', function (t) {
    CLIENT.getUuid({
        account: 'banks',
        type: 'role',
        names: [ 'borrower', 'lender' ]
    }, function (err, lookup) {
        t.ok(lookup.account);
        t.ok(lookup.uuids.borrower);
        t.ok(lookup.uuids.lender);
        t.end();
    });
}); teardown(test);

setup(test); test('authorize account self', function (t) {
    CLIENT.getAccount('banks', function (err, info) {
        var principal = info;
        var action = 'read';
        var resource = {
            owner: info,
            roles: []
        };
        var conditions = {
            activeRoles: []
        };
        var ok = CLIENT.authorize({
            principal: principal,
            action: action,
            resource: resource,
            conditions: conditions
        });
        t.ok(ok);
        t.end();
    });
}); teardown(test);
