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

"use strict";
var path = require('path');
var fs = require('fs');


var NAME_SEPARATOR='-';

/**
 * Utility methods for security.
 *
 *
 *
 *
 * @name caf_security/utils
 * @namespace
 */
exports.loadKey = function(dir, fileName, cb) {
    var keyFile = path.join(dir, fileName);
    fs.readFile(keyFile, 'utf8', cb);
};


/**
 * Splits a compound name into namespace root and local name. The convention
 * is to use the character '-' to separate them.
 *
 * @param {string} name A name to split.
 * @return {Array.<string>} An array with two elements: namespace root and
 * local name.
 *
 * @throws {Error} Invalid compound name.
 * @name  tokens/splitName
 * @function
 *
 */
var splitName = exports.splitName = function(name) {
    var result = name.split(NAME_SEPARATOR);
    if (result.length === 2) {
        return result;
    } else {
        var err = new Error('Invalid name');
        err.name = name;
        throw err;
    }
};
