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

var CLIENT = mahi.createClient({
    url: process.env.MAHI_TEST_URL || 'http://127.0.0.1:8080',
    typeTable: {
        'ip': 'ip'
    }
});

test('authenticate', function (t) {
    CLIENT.authenticate({
        account: 'banks',
        keyId: 'e3:4d:9b:26:bd:ef:a1:db:43:ae:4b:f7:bc:69:a7:24'
    }, function (err, info) {
        t.notOk(err);
        t.ok(info);
        t.end();
    });
});

test('authorize empty roles', function (t) {
    t.end();
});

test('authorize empty tags', function (t) {
    t.end();
});

test('getName', function (t) {
    var uuids = [
        'bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f',
        '1e77f528-9e64-11e3-8d12-838d40383bce',
        '2a05359a-9e64-11e3-816d-e7f87365cf40'
    ];
    CLIENT.getName({
        uuids: uuids
    }, function (err, lookup) {
        uuids.forEach(function (uuid) {
            t.ok(lookup[uuid]);
        });
        t.end();
    });
});

test('getUuid - account only', function (t) {
    CLIENT.getUuid({
        account: 'banks'
    }, function (err, lookup) {
        t.ok(lookup.account);
        t.end();
    });
});

test('getUuid - roles', function (t) {
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
});

test('clean up', function (t) {
    CLIENT.close();
    t.end();
});
