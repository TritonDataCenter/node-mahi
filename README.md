<!--
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
-->

<!--
    Copyright (c) 2014, Joyent, Inc.
    Copyright 2022 MNX Cloud, Inc.
-->

# node-mahi

This repository is part of Triton Data Center.  For contribution
guidelines, issues, and general documentation, visit the main
[Triton](http://github.com/TritonDataCenter/triton) project page.

This is the client for Mahi. When talking to mahi, translation and
authentication responses are cached. node-mahi also contains the authorization
API.

# Testing

Testing requires a Mahi server instance.  Point `MAHI_TEST_URL` at an existing
server that has been bootstrapped with the
[Mahi test data](https://github.com/TritonDataCenter/mahi/blob/master/test/data/test-nodeletes.ldif)
and run `make test`.
