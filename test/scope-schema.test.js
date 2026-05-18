/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * Unit tests for lib/scope-schema.js.
 *
 * The module is the canonical scope envelope schema
 * shared with sdc-cloudapi, manta-buckets-api, and
 * mahi.  validateScope() is fail-closed: any
 * malformed input must return {valid:false,
 * scope:null, error:<string>}.  These tests exercise
 * each rejection branch and the success path.
 */

var test = require('tap').test;
var schema = require('../lib/scope-schema');


// ---- Helpers ----

/**
 * @brief Build a permissions array of size n with
 *   unique short bucket names.  Used to exercise the
 *   MAX_PERMISSIONS branch without tripping the
 *   MAX_SCOPE_SIZE branch first.
 *
 * @param {number} n - Number of entries
 * @return {Array} permissions array
 */
function makePerms(n) {
    var out = [];
    var i;
    for (i = 0; i < n; i++) {
        out.push({bucket: 'b' + i, level: 'read'});
    }
    return (out);
}

/**
 * @brief Build a permissions array whose serialized
 *   JSON exceeds MAX_SCOPE_SIZE while keeping the
 *   entry count <= MAX_PERMISSIONS.  Each bucket
 *   name is 63 chars (max per S3 spec) and unique.
 *
 * @param {number} n - Number of entries
 * @return {Array} permissions array
 */
function makeFatPerms(n) {
    var prefix = '';
    var i;
    for (i = 0; i < 60; i++) {
        prefix += 'a';
    }
    var out = [];
    for (i = 0; i < n; i++) {
        var idx = ('000' + i).slice(-3);
        out.push({
            bucket: prefix + idx,
            level: 'readwrite'
        });
    }
    return (out);
}


// ---- validateScope: shape rejection ----

test('validateScope: null is rejected', function (t) {
    var r = schema.validateScope(null);
    t.equal(r.valid, false, 'invalid');
    t.equal(r.scope, null, 'scope null');
    t.ok(r.error, 'has error');
    t.end();
});

test('validateScope: undefined is rejected', function (t) {
    var r = schema.validateScope(undefined);
    t.equal(r.valid, false, 'invalid');
    t.ok(r.error, 'has error');
    t.end();
});

test('validateScope: string is rejected', function (t) {
    var r = schema.validateScope('not-an-object');
    t.equal(r.valid, false, 'invalid');
    t.ok(r.error, 'has error');
    t.end();
});

test('validateScope: number is rejected', function (t) {
    var r = schema.validateScope(42);
    t.equal(r.valid, false, 'invalid');
    t.ok(r.error, 'has error');
    t.end();
});

test('validateScope: array is rejected', function (t) {
    var r = schema.validateScope([]);
    t.equal(r.valid, false, 'array rejected');
    t.ok(r.error, 'has error');
    t.end();
});


// ---- validateScope: envelope rejection ----

test('validateScope: missing version', function (t) {
    var r = schema.validateScope({permissions: []});
    t.equal(r.valid, false, 'invalid');
    t.ok(/version/.test(r.error), 'mentions version');
    t.end();
});

test('validateScope: wrong version', function (t) {
    var r = schema.validateScope({
        version: 2,
        permissions: [
            {bucket: 'a', level: 'read'}
        ]
    });
    t.equal(r.valid, false, 'invalid');
    t.ok(/version/.test(r.error), 'mentions version');
    t.end();
});

test('validateScope: permissions not array', function (t) {
    var r = schema.validateScope({
        version: schema.SCOPE_VERSION,
        permissions: 'oops'
    });
    t.equal(r.valid, false, 'invalid');
    t.ok(/array/.test(r.error), 'mentions array');
    t.end();
});

test('validateScope: empty permissions', function (t) {
    var r = schema.validateScope({
        version: schema.SCOPE_VERSION,
        permissions: []
    });
    t.equal(r.valid, false, 'invalid');
    t.ok(/empty/.test(r.error), 'mentions empty');
    t.end();
});

test('validateScope: too many permissions', function (t) {
    var perms = makePerms(schema.MAX_PERMISSIONS + 1);
    var r = schema.validateScope({
        version: schema.SCOPE_VERSION,
        permissions: perms
    });
    t.equal(r.valid, false, 'invalid');
    t.ok(/maximum/.test(r.error), 'mentions maximum');
    t.end();
});

test('validateScope: oversize JSON', function (t) {
    /*
     * 600 entries x ~93 bytes/entry > 51200 bytes
     * but still <= MAX_PERMISSIONS, so the size
     * branch fires before the count branch.
     */
    var perms = makeFatPerms(600);
    var r = schema.validateScope({
        version: schema.SCOPE_VERSION,
        permissions: perms
    });
    t.equal(r.valid, false, 'invalid');
    t.ok(/size limit/.test(r.error), 'mentions size');
    t.end();
});


// ---- validateScope: per-entry rejection ----

test('validateScope: entry not object', function (t) {
    var r = schema.validateScope({
        version: schema.SCOPE_VERSION,
        permissions: [null]
    });
    t.equal(r.valid, false, 'invalid');
    t.ok(/permissions\[0\]/.test(r.error), 'index');
    t.end();
});

test('validateScope: bucket too short', function (t) {
    var r = schema.validateScope({
        version: schema.SCOPE_VERSION,
        permissions: [
            {bucket: '', level: 'read'}
        ]
    });
    t.equal(r.valid, false, 'invalid');
    t.ok(/bucket/.test(r.error), 'mentions bucket');
    t.end();
});

test('validateScope: bucket too long', function (t) {
    var name = '';
    var i;
    for (i = 0; i < schema.MAX_BUCKET_LENGTH + 1; i++) {
        name += 'a';
    }
    var r = schema.validateScope({
        version: schema.SCOPE_VERSION,
        permissions: [
            {bucket: name, level: 'read'}
        ]
    });
    t.equal(r.valid, false, 'invalid');
    t.ok(/bucket/.test(r.error), 'mentions bucket');
    t.end();
});

test('validateScope: bucket non-string', function (t) {
    var r = schema.validateScope({
        version: schema.SCOPE_VERSION,
        permissions: [
            {bucket: 5, level: 'read'}
        ]
    });
    t.equal(r.valid, false, 'invalid');
    t.end();
});

test('validateScope: invalid bucket chars', function (t) {
    var r = schema.validateScope({
        version: schema.SCOPE_VERSION,
        permissions: [
            {bucket: 'NoCaps', level: 'read'}
        ]
    });
    t.equal(r.valid, false, 'invalid');
    t.ok(/invalid/.test(r.error), 'mentions invalid');
    t.end();
});

test('validateScope: non-trailing wildcard', function (t) {
    var r = schema.validateScope({
        version: schema.SCOPE_VERSION,
        permissions: [
            {bucket: 'pre*mid', level: 'read'}
        ]
    });
    t.equal(r.valid, false, 'invalid');
    t.ok(/wildcard/.test(r.error), 'mentions wildcard');
    t.end();
});

test('validateScope: invalid level', function (t) {
    var r = schema.validateScope({
        version: schema.SCOPE_VERSION,
        permissions: [
            {bucket: 'a', level: 'admin'}
        ]
    });
    t.equal(r.valid, false, 'invalid');
    t.ok(/level/.test(r.error), 'mentions level');
    t.end();
});

test('validateScope: duplicate bucket', function (t) {
    var r = schema.validateScope({
        version: schema.SCOPE_VERSION,
        permissions: [
            {bucket: 'logs', level: 'read'},
            {bucket: 'logs', level: 'full'}
        ]
    });
    t.equal(r.valid, false, 'invalid');
    t.ok(/duplicate/.test(r.error), 'mentions dup');
    t.end();
});


// ---- validateScope: success path ----

test('validateScope: minimal valid scope', function (t) {
    var r = schema.validateScope({
        version: schema.SCOPE_VERSION,
        permissions: [
            {bucket: 'logs', level: 'read'}
        ]
    });
    t.equal(r.valid, true, 'valid');
    t.equal(r.error, null, 'no error');
    t.equal(typeof (r.scope), 'string',
        'scope is JSON');
    var parsed = JSON.parse(r.scope);
    t.equal(parsed.version, schema.SCOPE_VERSION,
        'version preserved');
    t.equal(parsed.permissions.length, 1, '1 entry');
    t.end();
});

test('validateScope: all levels and wildcard',
    function (t) {
        var r = schema.validateScope({
            version: schema.SCOPE_VERSION,
            permissions: [
                {bucket: '*', level: 'read'},
                {bucket: 'logs-*', level: 'readwrite'},
                {bucket: 'archive', level: 'full'}
            ]
        });
        t.equal(r.valid, true, 'valid');
        t.equal(r.error, null, 'no error');
        t.end();
    });

test('validateScope: at MAX_PERMISSIONS boundary',
    function (t) {
        var perms = makePerms(schema.MAX_PERMISSIONS);
        var r = schema.validateScope({
            version: schema.SCOPE_VERSION,
            permissions: perms
        });
        t.equal(r.valid, true, 'valid');
        t.end();
    });


// ---- isValidBucketPattern smoke ----

test('isValidBucketPattern: accepts exact', function (t) {
    t.ok(schema.isValidBucketPattern('logs'));
    t.ok(schema.isValidBucketPattern('a-b.c'));
    t.ok(schema.isValidBucketPattern('0abc'));
    t.end();
});

test('isValidBucketPattern: accepts wildcard',
    function (t) {
        t.ok(schema.isValidBucketPattern('*'));
        t.ok(schema.isValidBucketPattern('logs-*'));
        t.end();
    });

test('isValidBucketPattern: rejects bad input',
    function (t) {
        t.notOk(schema.isValidBucketPattern(''));
        t.notOk(schema.isValidBucketPattern('UPPER'));
        t.notOk(schema.isValidBucketPattern('pre*mid'));
        t.notOk(schema.isValidBucketPattern('-leading'));
        t.notOk(schema.isValidBucketPattern('.dot'));
        t.end();
    });


// ---- matchBucketPattern smoke ----

test('matchBucketPattern: exact match', function (t) {
    t.ok(schema.matchBucketPattern('foo', 'foo'));
    t.notOk(schema.matchBucketPattern('foo', 'bar'));
    t.notOk(schema.matchBucketPattern('foo', 'foobar'));
    t.end();
});

test('matchBucketPattern: wildcard', function (t) {
    t.ok(schema.matchBucketPattern('*', 'anything'));
    t.ok(schema.matchBucketPattern('logs-*',
        'logs-2026'));
    t.notOk(schema.matchBucketPattern('logs-*',
        'archive'));
    t.end();
});


// ---- parseScope ----

test('parseScope: invalid JSON returns null',
    function (t) {
        t.equal(schema.parseScope('not json'), null);
        t.end();
    });

test('parseScope: wrong version returns null',
    function (t) {
        var raw = JSON.stringify({
            version: 99,
            permissions: []
        });
        t.equal(schema.parseScope(raw), null);
        t.end();
    });

test('parseScope: well-formed returns object',
    function (t) {
        var raw = JSON.stringify({
            version: schema.SCOPE_VERSION,
            permissions: [
                {bucket: 'a', level: 'read'}
            ]
        });
        var parsed = schema.parseScope(raw);
        t.ok(parsed, 'parsed');
        t.equal(parsed.version, schema.SCOPE_VERSION);
        t.equal(parsed.permissions.length, 1);
        t.end();
    });
