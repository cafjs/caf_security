// Modifications copyright 2020 Caf.js Labs and contributors
/*!
Copyright 2013 Hewlett-Packard Development Company, L.P.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

'use strict';
const path = require('path');
const fs = require('fs');
const cli = require('caf_cli');
const json_rpc = require('caf_transport').json_rpc;

/**
 * Utility methods for security.
 *
 * @module caf_security/utils
 */

/**
 * Loads a key from a file.
 *
 * @param {string} dir A directory.
 * @param {string} fileName The name of a key file.
 * @param {cbType} cb A callback to return the contents of the file or an error.
 *
 * @memberof! module:caf_security/utils
 * @alias loadKey
 *
 */
exports.loadKey = function(dir, fileName, cb) {
    const keyFile = path.join(dir, fileName);
    fs.readFile(keyFile, 'utf8', cb);
};

/**
 * Creates a session with the accounts service.
 *
 * @param {Object|null} accounts An optional already negotiated session.
 * @param {string} accountsURL The url for the accounts service.
 * @param {string|null} caOwner The requester owner.
 * @param {function} closeF  A function of type `function(error=)` to notify
 * when the session closed, and whether there was an error.
 * @param {cbType} cb A callback to return the session with the accounts
 * service.
 *
 * @memberof! module:caf_security/utils
 * @alias accountsSession
 *
 */
exports.accountsSession = function(accounts, accountsURL, caOwner, closeF, cb) {
    if (accounts) {
        process.nextTick(function() { cb(null, accounts);});
    } else {
        const from = 'NOBODY-' +
          (caOwner ?
              caOwner.substring(0, json_rpc.ACCOUNTS_CA_LENGTH) :
              'UNKNOWN');
        const result = new cli.Session(accountsURL, from, {
            disableBackchannel: true,
            from: from
        });
        result.onopen = function() {
            cb(null, result);
        };

        result.onclose = closeF;
    }
};
