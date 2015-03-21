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
/**
 * Client implementation of srp utils
 *
 * @name caf_security/srpUtils
 * @namespace
 */

var exports = module.exports = require('./srpUtilsCommon');

var tokens = require('./tokens');

// Duplicate of tokens.similar() to avoid including tokens.js in browser version
var similarTokens = exports.similarTokens = function(t1, t2, ignoreExpires) {
    return tokens.similar(t1, t2, ignoreExpires);
};

var decodeToken = exports.decodeToken = function(tokStr) {
    return tokens.decode(tokStr);
};


var splitName = exports.splitName = function(name) {
    return tokens.splitName(name);
};
