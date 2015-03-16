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
var assert = require('assert');
var jwt = require('jsonwebtoken');

/**
 * Tokens are the primary mechanism to implement  safe single sign on for all
 *  the user apps. Within an app, a token is used by the client to create a
 * secure channel with its corresponding CA running in the cloud.
 *
 * We use the JSON Web Tokens (draft-ietf-oauth-json-web-token-32) format for
 *  our tokens.
 *
 * Not all apps are equally trusted, and we want to ensure that a rogue app
 *  cannot reuse tokens in a different context. We achieve that by weakening
 * tokens with the following optional constraints:
 *
 *    appPublisher: publisher of the app hosting CAs.
 *
 *    appLocalName: name of the app in the 'appPublisher' context.
 *
 *    caOwner: owner of the CA.
 *
 *    caLocalName: name of the CA in the owner's context.
 *
 *    expiresAfter: Expire time of token in milliseconds since midnight
 *  January 1,1970 UTC
 *
 * Tokens form  a meet semi-lattice, where a meet (^) operator defines a
 *  partial ordering of tokens, i.e.,:
 *
 *                  A^B = A iff A <= B
 *
 * and this makes it much simpler to weaken tokens. In fact, in CAF if you have
 *  a valid token you can always request a weaker one regardless of who you
 * are. Providing a service to manage user tokens becomes trivial.
 *
 * The meet (^) operator is just simply set intersection for each of the
 *  constraints:
 *
 *             a^a = a
 *             a^* = a
 *             *^b = b
 *             a^b = 'empty' when (a !== b and a !== * and b !== *)
 *
 * and in the case of 'expiresAfter', pick the shortest deadline.
 *
 * ACLs (Access Control Lists) are also expressed with the same semi-lattice,
 * using the meet operator for access checks:
 *
 *         ALLOW if  ACL[i] ^ Token != empty    for some ACL[i] in ACL
 *
 * where the result of ^ is 'empty' if any of the constraints has an
 *  'empty' set.
 *
 *
 * @name caf_security/tokens
 * @namespace
 */

var EXPIRES_AFTER = 'expiresAfter';
var CONSTRAINTS = ['appPublisher', 'appLocalName', 'caOwner', 'caLocalName',
                   EXPIRES_AFTER];

var SIGNATURE_ALGO = 'RS256'; // RSA asymetric keys with SHA256

var NAME_SEPARATOR='-';

/**
 * 'Meet' (^)  operation of two tokens. Performs set intersection for each
 * constraint, and if any resulting constraint is empty it returns 'null', the
 *  empty token.
 *
 *  A missing constraint is assumed to be '*', i.e., all element in the set.
 *
 *  Intersection of `expiresAfter` uses time intervals.
 *
 *  There is no validation of the tokens or signing of the result.
 *
 * @param {caf.token} t1 A token to combine with the 'meet' operator.
 * @param {caf.token} t2 A token to combine with the 'meet' operator.
 *
 * @return {caf.token | null} Null if the resulting set is empty or an unsigned
 *  token payload with 't1^t2'.
 *
 * @name  tokens/meet
 * @function
 */
var meet = exports.meet = function(t1, t2) {
    var meetOne = function(x, y, isTime) {
        if (x === undefined) {
            return y;
        } else if (y === undefined) {
            return x;
        } else if (x === y) {
            return x;
        } else {
            if (isTime) {
                return Math.min(x, y);
            } else {
                return null;
            }
        }
    };

    assert.equal(typeof t1, 'object', "'t1' not an object");
    assert.equal(typeof t2, 'object', "'t2' not an object");
    if ((t1 === null) || (t2 === null)) {
        return null;
    }

    var result = {};
    var isEmpty = CONSTRAINTS.some(function(x) {
                                       var m = meetOne(t1[x], t2[x],
                                                       (x === EXPIRES_AFTER));
                                       if (m === null) {
                                           return true;
                                       } else {
                                           if (m !== undefined) {
                                               result[x] = m;
                                           }
                                           return false;
                                       }
                                   });
    if (isEmpty) {
        return null;
    } else {
        return result;
    }
};

/**
 * Deep equality of two tokens ignoring fields that are not constraints.
 *
 * Note that 'null' represents the empty token.
 *
 * @param {caf.token} t1 A token to compare.
 * @param {caf.token} t2 A token to compare.
 * @param {boolean} ignoreExpires True if we ignore the token expire date.
 *
 * @return {boolean} t1 similarTo t2
 *
 * @name  tokens/similar
 * @function
 */
var similar = exports.similar = function(t1, t2, ignoreExpires) {
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


/**
 * Whether for tokens t1 and t2, t1 <= t2.
 *
 * Note that 'null' represents the empty token, and 'null' <= t2 for all t2.
 *
 * @param {caf.token} t1 A token to compare.
 * @param {caf.token} t2 A token to compare.
 * @return {boolean} t1 <= t2
 *
 * @throws {Error} Malformed token.
 *
 * @name  tokens/lessOrEqual
 * @function
 */
var lessOrEqual = exports.lessOrEqual = function(t1, t2) {
    assert.equal(typeof t1, 'object', "'t1' not an object");
    assert.equal(typeof t2, 'object', "'t2' not an object");

    return similar(meet(t1, t2), t1);
};

/**
 * Signs a token.
 *
 * @param {caf.token} token Token to sign.
 * @param {Object} privKey Private key for signing.
 *
 * @return {string} A serialized signed token.
 * @throws {Error}  Cannot sign.
 *
 * @name  tokens/sign
 * @function
 */
var sign = exports.sign = function(token, privKey) {
    return jwt.sign(token,  privKey, {algorithm: SIGNATURE_ALGO});
};

var checkToken = function(token) {
    return !CONSTRAINTS.some(function(x) {
                                 if (token[x] === undefined) {
                                     return false;
                                 } else if (x === EXPIRES_AFTER) {
                                     return !(typeof token[x] === 'number');
                                 } else if (typeof token[x] !== 'string') {
                                     return true;
                                 } else if (token[x]
                                            .match(/^[a-z0-9]+$/i) === null) {
                                     // ASCII characters and numbers only
                                     return true;
                                 } else {
                                     return false;
                                 }
                             });
};

/**
 *  Checks whether a username contains only valid characters (ASCII + numbers)
 *
 * @param {string} username A username to check.
 * @return {boolean} True if ok, false otherwise.
 *
 */
var validUsername = exports.validUsername = function(username) {
    return (username.match(/^[a-z0-9]+$/i) !== null);
};

/**
 * Validates a token.
 *
 * Checks signature, expire time, and string format (ASCII alphanumeric).
 *
 *
 * @param {string} tokenStr A string with the encoded token.
 * @param {Object} pubKey A public key to validate the token
 *
 * @return{caf.token} A decoded valid token.
 *
 * @throws {Error} Token does not validate
 *
 * @name  tokens/validate
 * @function
 */
var validate = exports.validate = function(tokenStr, pubKey) {
    var token = jwt.verify(tokenStr, pubKey);
    if (!checkToken(token)) {
        var err = new Error('Malformed token');
        err.token = token;
        throw err;
    }
    if (typeof token[EXPIRES_AFTER] === 'number') {
        if (Date.now() > token[EXPIRES_AFTER]) {
            var error = new Error('Expired token');
            error.token = token;
            throw error;
        }
    }
    return token;
};

/**
 * Decode a token without doing any checks. This is sometimes useful to choose
 * a public key for validation.
 *
 * @param {string} tokenStr A string encoding a token.
 *
 * @return {caf.token} An untrusted token that has NOT been validated.
 *
 */
var decode = exports.decode = function(tokenStr) {
    return jwt.decode(tokenStr);
};


/**
 * Checks whether a valid token satisfies an ACL (Access control List).
 *
 * Inefficient with many ACLs. See `./rules.js` for a recommended alternative.
 *
 *
 * @param {Array.<caf.token>| caf.token} acl An ACL formed with one or an array
 *  of constraints using a token format.
 * @param {caf.token} token A previously validated token to check 'acl'.
 *
 * @return {boolean} True if satisfies at least one element of the ACL.
 *
 * @name  tokens/satisfyACL
 * @function
 */
var satisfyACL = exports.satisfyACL = function(acl, token) {
    assert.equal(typeof acl, 'object', "'acl' not an object");
    assert.equal(typeof token, 'object', "'token' not an object");
    if (!Array.isArray(acl)) {
        acl = [acl];
    }

    return acl.some(function(ac) { return (meet(ac, token) !== null); });
};

/**
 * Constructor for a new token or acl element payload.
 *
 * The type of caf.token is {appPublisher: string=, appLocalName:string=,
 *                           caOwner: string=, caLocalName: string=,
 *                           expiresAfter: string=}
 *
 *  @param {string=} appPublisher Publisher of the app hosting CAs.
 * @param {string=} appLocalName Name of the app in the 'appPublisher' context.
 * @param {string=} caOwner  Owner of the CA.
 * @param {string=} caLocalName Name of the CA in the owner's context.
 * @param {number=} durationInMsec Time in msec from 'now' till token expires.
 *
 * @return {caf.token} A token or acl element payload.
 *
 * @throws {Error} when input is malformed.
 *
 * @name  tokens/newPayload
 * @function
 */
var newPayload = exports.newPayload = function(appPublisher, appLocalName,
                                               caOwner, caLocalName,
                                               durationInMsec) {
    var result = {};

    var checkAndSetArg = function(arg, argName) {
        if (arg) {
            assert.ok(typeof arg === 'string',
                      "'" + argName + "' is not a string");
            assert.ok(arg.match(/^[a-z0-9]+$/i) !== null,
                      "'" + argName + "'  has invalid characters:" + arg);
            result[argName] = arg;
        }
    };

    checkAndSetArg(appPublisher, 'appPublisher');
    checkAndSetArg(appLocalName, 'appLocalName');
    checkAndSetArg(caOwner, 'caOwner');
    checkAndSetArg(caLocalName, 'caLocalName');

    durationInMsec && assert.ok(typeof durationInMsec === 'number',
                                "'durationInMsec' is not a number");
    (typeof durationInMsec === 'number') &&
        assert.ok(durationInMsec > 0, "'durationInMsec' is not positive");

    if (durationInMsec) {
        result.expiresAfter = Date.now() + durationInMsec;
    }

    return result;
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
