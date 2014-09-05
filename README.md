<!--
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
-->

<!--
    Copyright (c) 2014, Joyent, Inc.
-->

# node-mahi

This repository is part of the Joyent SmartDataCenter project (SDC).  For
contribution guidelines, issues, and general documentation, visit the main
[SDC](http://github.com/joyent/sdc) project page.

This is the client for Mahi. When talking to mahi, translation and
authentication responses are cached. node-mahi also contains the authorization
API.

# Testing

Testing requires a Mahi server instance. Point MAHI_TEST_URL at the test
instance and run `make test`.
