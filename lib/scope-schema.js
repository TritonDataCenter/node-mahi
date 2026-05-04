/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * Canonical per-bucket access key scope schema.
 *
 * This module is the single source of truth for the
 * scope data format shared across sdc-cloudapi,
 * manta-buckets-api, and mahi.  sdc-ufds has its own
 * validation (LDAP schema layer) but must agree with
 * the constants defined here.
 *
 * Scope envelope:
 *   {
 *     "version": 1,
 *     "permissions": [
 *       { "bucket": "<name-or-pattern>",
 *         "level": "read|readwrite|full" }
 *     ]
 *   }
 *
 * Wildcard grammar:
 *   "*"       — matches all buckets
 *   "prefix*" — trailing wildcard
 *   "exact"   — exact match only
 *   Non-trailing wildcards are rejected.
 *
 * Absent/null scope = unrestricted (backward compat).
 */


// ---- Constants ----

/**
 * @brief Permission levels (string values)
 *
 * These are the only valid values for the "level"
 * field in a scope permission entry.
 */
var VALID_LEVELS = ['read', 'readwrite', 'full'];

/**
 * @brief Numeric permission level constants
 *
 * Higher value = more permissive.  Used for
 * comparison: a granted level >= required level
 * means access is allowed.
 */
var LEVEL_READ = 1;
var LEVEL_READWRITE = 2;
var LEVEL_FULL = 3;

/**
 * @brief Map from level string to numeric constant
 */
var LEVEL_MAP = {
    read: LEVEL_READ,
    readwrite: LEVEL_READWRITE,
    full: LEVEL_FULL
};

/**
 * @brief Current scope schema version
 */
var SCOPE_VERSION = 1;

/**
 * @brief Maximum permissions entries per scope
 */
var MAX_PERMISSIONS = 1000;

/**
 * @brief Maximum scope JSON size in bytes
 */
var MAX_SCOPE_SIZE = 51200;

/**
 * @brief Minimum bucket name length
 */
var MIN_BUCKET_LENGTH = 1;

/**
 * @brief Maximum bucket name length (AWS S3 spec)
 */
var MAX_BUCKET_LENGTH = 63;


// ---- Validation functions ----

/**
 * @brief Validate a bucket name or pattern against
 *   S3 naming rules
 *
 * Allows exact names, trailing wildcard (logs-*),
 * or bare wildcard (*).  Rejects non-trailing
 * wildcards (*-logs, pre-*-mid).
 *
 * Valid chars: lowercase letters, numbers, hyphens,
 * periods (per AWS bucket naming spec).
 *
 * @param {string} pattern - Bucket name or pattern
 * @return {boolean} true if valid
 */
function isValidBucketPattern(pattern) {
    if (pattern === '*') {
        return (true);
    }

    /*
     * Reject non-trailing wildcards: '*' only valid
     * as the last character.
     */
    var starPos = pattern.indexOf('*');
    if (starPos !== -1 &&
        starPos !== pattern.length - 1) {
        return (false);
    }

    /* Strip trailing wildcard for base validation */
    var name = pattern;
    if (name.charAt(name.length - 1) === '*') {
        name = name.substring(0, name.length - 1);
    }
    if (name.length === 0) {
        return (false);
    }
    return (/^[a-z0-9][a-z0-9.\-]*$/.test(name));
}

/**
 * @brief Match a bucket name against a scope pattern
 *
 * Runtime matching (not validation).  Supports exact
 * match, bare wildcard, and trailing wildcard.
 *
 * @param {string} pattern - Scope pattern
 * @param {string} name - Actual bucket name
 * @return {boolean} true if pattern matches name
 */
function matchBucketPattern(pattern, name) {
    if (pattern === '*') {
        return (true);
    }
    if (pattern.charAt(pattern.length - 1) === '*') {
        var prefix = pattern.substring(
            0, pattern.length - 1);
        return (name.indexOf(prefix) === 0);
    }
    return (pattern === name);
}

/**
 * @brief Parse and validate a scope JSON string
 *
 * Returns the parsed scope object or null on any
 * validation failure (fail closed).
 *
 * @param {string} raw - JSON scope string
 * @return {Object|null} Parsed scope or null
 */
function parseScope(raw) {
    var scope;
    try {
        scope = JSON.parse(raw);
    } catch (e) {
        return (null);
    }

    if (!scope ||
        scope.version !== SCOPE_VERSION ||
        !Array.isArray(scope.permissions)) {
        return (null);
    }

    return (scope);
}

/**
 * @brief Validate a scope object (full validation)
 *
 * Performs complete validation of a scope envelope
 * including all permission entries.  Returns an
 * object with valid flag, canonical JSON string,
 * and error message.
 *
 * Time complexity:  O(n) where n = permissions count
 * Space complexity: O(n) for duplicate check
 *
 * @param {Object} scope - Scope envelope object
 * @return {Object} {valid, scope, error}
 */
function validateScope(scope) {
    if (!scope || typeof (scope) !== 'object' ||
        Array.isArray(scope)) {
        return ({
            valid: false,
            scope: null,
            error: 'scope: must be an object with' +
                ' version and permissions fields'
        });
    }

    if (scope.version !== SCOPE_VERSION) {
        return ({
            valid: false,
            scope: null,
            error: 'scope: version must be ' +
                SCOPE_VERSION
        });
    }

    if (!Array.isArray(scope.permissions)) {
        return ({
            valid: false,
            scope: null,
            error: 'scope: permissions must be' +
                ' an array'
        });
    }

    if (scope.permissions.length === 0) {
        return ({
            valid: false,
            scope: null,
            error: 'scope: permissions array is empty'
        });
    }

    if (scope.permissions.length > MAX_PERMISSIONS) {
        return ({
            valid: false,
            scope: null,
            error: 'scope: exceeds maximum of ' +
                MAX_PERMISSIONS + ' entries'
        });
    }

    var scopeJson = JSON.stringify(scope);
    if (scopeJson.length > MAX_SCOPE_SIZE) {
        return ({
            valid: false,
            scope: null,
            error: 'scope: JSON exceeds ' +
                (MAX_SCOPE_SIZE / 1024) +
                'KB size limit'
        });
    }

    var seen = {};
    for (var i = 0; i < scope.permissions.length; i++) {
        var p = scope.permissions[i];
        if (!p || typeof (p) !== 'object') {
            return ({
                valid: false,
                scope: null,
                error: 'scope: permissions[' + i +
                    '] must be an object'
            });
        }
        if (typeof (p.bucket) !== 'string' ||
            p.bucket.length < MIN_BUCKET_LENGTH ||
            p.bucket.length > MAX_BUCKET_LENGTH) {
            return ({
                valid: false,
                scope: null,
                error: 'scope: permissions[' + i + '].bucket must be ' +
                    MIN_BUCKET_LENGTH + '-' + MAX_BUCKET_LENGTH + ' characters'
            });
        }
        if (!isValidBucketPattern(p.bucket)) {
            return ({
                valid: false,
                scope: null,
                error: 'scope: permissions[' + i +
                    '].bucket: invalid characters' + ' or wildcard position'
            });
        }
        if (VALID_LEVELS.indexOf(p.level) === -1) {
            return ({
                valid: false,
                scope: null,
                error: 'scope: permissions[' + i + '].level must be one of: ' +
                    VALID_LEVELS.join(', ')
            });
        }
        if (seen[p.bucket]) {
            return ({
                valid: false,
                scope: null,
                error: 'scope: duplicate bucket' + ' pattern \'' + p.bucket +
                    '\''
            });
        }
        seen[p.bucket] = true;
    }

    return ({valid: true, scope: scopeJson, error: null});
}


module.exports = {
    /* Constants */
    VALID_LEVELS: VALID_LEVELS,
    LEVEL_READ: LEVEL_READ,
    LEVEL_READWRITE: LEVEL_READWRITE,
    LEVEL_FULL: LEVEL_FULL,
    LEVEL_MAP: LEVEL_MAP,
    SCOPE_VERSION: SCOPE_VERSION,
    MAX_PERMISSIONS: MAX_PERMISSIONS,
    MAX_SCOPE_SIZE: MAX_SCOPE_SIZE,
    MIN_BUCKET_LENGTH: MIN_BUCKET_LENGTH,
    MAX_BUCKET_LENGTH: MAX_BUCKET_LENGTH,

    /* Validation */
    isValidBucketPattern: isValidBucketPattern,
    validateScope: validateScope,

    /* Runtime */
    matchBucketPattern: matchBucketPattern,
    parseScope: parseScope
};
