<!--
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
-->

<!--
    Copyright (c) 2014, Joyent, Inc.
    Copyright 2025 Edgecast Cloud LLC.
-->

# node-mahi

This repository is part of Triton Data Center.  For contribution
guidelines, issues, and general documentation, visit the main
[Triton](http://github.com/TritonDataCenter/triton) project page.

This is the client for Mahi. When talking to mahi, translation and
authentication responses are cached. node-mahi also contains the authorization
API.

## Authentication Methods

node-mahi supports two authentication methods:

### SSH Key Authentication (Traditional)
- `verifySignature(opts, cb)` - Verifies SSH key signatures

### AWS SigV4 Authentication (S3 API Compatibility)
- `getUserByAccessKey(accessKeyId, cb)` - Look up user by access key ID
- `verifySigV4(request, cb)` - Verify AWS Signature Version 4 authentication

## AWS S3 API Integration

For S3 API compatibility, use the SigV4 authentication methods:

```javascript
var mahi = require('node-mahi').createClient({
    url: 'http://mahi.example.com'
});

// Look up user by access key (for S3 gateway integration)
mahi.getUserByAccessKey('AKIA123456789EXAMPLE', function(err, user) {
    if (err) {
        console.error('Access key lookup failed:', err);
        return;
    }
    console.log('User:', user.login);
});

// Verify SigV4 signature
mahi.verifySigV4(httpRequest, function(err, result) {
    if (err) {
        console.error('SigV4 verification failed:', err);
        return;
    }
    console.log('Authentication successful:', result.accessKeyId);
});
```

### S3 Client Compatibility

TBD

# Testing

Testing requires a Mahi server instance.  Point `MAHI_TEST_URL` at an existing
server that has been bootstrapped with the
[Mahi test data](https://github.com/TritonDataCenter/mahi/blob/master/test/data/test-nodeletes.ldif)
and run `make test`.
