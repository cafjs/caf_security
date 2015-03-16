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
 * Client implementation of srp
 *
 * @name caf_security/srpUtils
 * @namespace
 */
var crypto = require('crypto');
var srp = require('srp');
var assert = require('assert');
var tokens = require('./tokens');

var NUM_BITS = "2048";
var SALT_BYTES = 32;
var KEY_BYTES = 32;
var PARAMS = exports.PARAMS = srp.params[NUM_BITS];

var ENCRYPTION_ALGO = 'AES-256-CTR';


var bufToHex = exports.bufToHex = function(buf) {
    return buf.toString('hex');
};

var hexToBuf = exports.hexToBuf = function(hex) {
    return Buffer(hex, 'hex');
};

var newSalt = exports.newSalt = function() {
    return crypto.randomBytes(SALT_BYTES);
};

var newSecret = exports.newSecret = function() {
     return crypto.randomBytes(KEY_BYTES);
};

var encryptToken = exports.encryptToken = function(key, tokenStr) {
    var cipher = crypto.createCipher(ENCRYPTION_ALGO, key);
    var tokenEnc = cipher.update(tokenStr, 'utf8', 'hex');
    tokenEnc += cipher.final('hex');
    return tokenEnc;
};

var decryptToken = exports.decryptToken = function(key, tokenEnc) {
    var decipher = crypto.createDecipher(ENCRYPTION_ALGO, key);
    var tokenStr = decipher.update(tokenEnc, 'hex', 'utf8');
    tokenStr += decipher.final('utf8');
    return tokenStr;
};

var strToBuffer = exports.strToBuffer = function(str) {
    return Buffer(str, 'utf8');
};

// Duplicate of tokens.similar() to avoid including tokens.js in browser version
var similarTokens = exports.similarTokens = function(t1, t2, ignoreExpires) {
    return tokens.similar(t1, t2, ignoreExpires);
};

var decodeToken = exports.decodeToken = function(tokStr) {
    return tokens.decode(tokStr);
};

