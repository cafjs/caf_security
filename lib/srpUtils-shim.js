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
 * Client implementation of srp utils for the browser.
 *
 * @name caf_security/srpUtils-shim
 * @namespace
 */
var exports = module.exports = require('./srpUtilsCommon');

var assert = require('assert');
var jwt_decode = require('jwt-decode');

var EXPIRES_AFTER = 'expiresAfter';
var CONSTRAINTS = ['appPublisher', 'appLocalName', 'caOwner', 'caLocalName',
                   EXPIRES_AFTER];

// Duplicate of tokens.similar() to avoid including tokens.js in browser version
var similarTokens = exports.similarTokens = function(t1, t2, ignoreExpires) {
    assert.equal(typeof t1, 'object', "'t1' not an object");
    assert.equal(typeof t2, 'object', "'t2' not an object");
    if ((t1 === null) || (t2 === null)) {
        return (t1 === t2);
    } else {
        return !CONSTRAINTS.some(function(x) {
                                     if (ignoreExpires &&
                                         (x === EXPIRES_AFTER)){
                                         return false;
                                     } else {
                                         return (t1[x] !== t2[x]);
                                     }
                                 });
    }
};

// Duplicate of tokens.decode() to avoid including tokens.js in browser version
var decodeToken = exports.decodeToken = function(tokStr) {
    return jwt_decode(tokStr);
};


var NAME_SEPARATOR='-';

// Duplicate of tokens.splitName () to avoid including tokens.js in browser
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
