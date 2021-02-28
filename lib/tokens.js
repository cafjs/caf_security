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
const assert = /** @type {typeof import('assert')} */(require('assert'));
const jwt = require('jsonwebtoken');
const json_rpc = require('caf_transport').json_rpc;

/**
 * Tokens are the primary mechanism to implement single sign on for all
 *  the user apps.
 *
 * A token is used by the client to create a
 * secure channel with its corresponding CA running in the cloud.
 *
 * We use the JSON Web Tokens (draft-ietf-oauth-json-web-token-32) format for
 *  our tokens.
 *
 * Not all apps are equally trusted, and we want to ensure that a rogue app
 * cannot reuse tokens in a different context.
 *
 * We achieve that by weakening tokens with the following optional constraints:
 *
 *  *  `appPublisher`: publisher of the app hosting CAs.
 *
 *  *  `appLocalName`: name of the app in the `appPublisher` context.
 *
 *  *  `caOwner`: owner name of the CA.
 *
 *  *  `caLocalName`: name of the CA in the owner's context.
 *
 *  *  `expiresAfter`: Expire time of token in milliseconds since midnight
 *  January 1,1970 UTC
 *
 * Tokens form a meet semi-lattice, where a meet (`^`) operator defines a
 *  partial ordering of tokens, i.e.,:
 *
 *                  A^B = A iff A <= B
 *
 * and this makes it much simpler to weaken tokens.
 *
 * In fact, in CAF if you have a valid token you can always request a weaker
 * one regardless of who you are. Providing a service to manage user tokens
 * becomes trivial.
 *
 * The meet (^) operator is just simply set intersection for each of the
 *  constraints:
 *
 *             a^a = a
 *             a^* = a
 *             *^b = b
 *             a^b = 'empty' when (a !== b and a !== * and b !== *)
 *
 * and in the case of `expiresAfter`, pick the shortest deadline.
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
 * @module caf_security/tokens
 */

const EXPIRES_AFTER = 'expiresAfter';
const CONSTRAINTS = [
    'appPublisher', 'appLocalName', 'caOwner', 'caLocalName', EXPIRES_AFTER
];

const SIGNATURE_ALGO = 'RS256'; // RSA asymetric keys with SHA256


const meet =
/**
 * 'Meet' (^)  operation of two tokens. Performs set intersection for each
 * constraint, and if any resulting constraint is empty it returns `null`, the
 *  empty token.
 *
 *  A missing constraint is assumed to be `*`, i.e., all the elements in the
 *  set.
 *
 *  Intersection of `expiresAfter` uses time intervals.
 *
 *  There is no validation of the tokens or signing of the result.
 *
 * @param {tokenType} t1 A token to combine with the 'meet' operator.
 * @param {tokenType} t2 A token to combine with the 'meet' operator.
 *
 * @return {tokenType | null} Null if the resulting set is empty or an unsigned
 *  token payload with 't1^t2'.
 *
 * @memberof! module:caf_security/tokens
 * @alias meet
 */
exports.meet = function(t1, t2) {
    const meetOne = function(x, y, isTime) {
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

    const result = {};
    const isEmpty = CONSTRAINTS.some(function(x) {
        const m = meetOne(t1[x], t2[x], (x === EXPIRES_AFTER));
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

const similar =
/**
 * Deep equality of two tokens ignoring fields that are not constraints.
 *
 * Note that `null` represents the empty token.
 *
 * @param {tokenType} t1 A token to compare.
 * @param {tokenType} t2 A token to compare.
 * @param {boolean} ignoreExpires True if we ignore the token expire date.
 *
 * @return {boolean} t1 similarTo t2
 *
 * @memberof! module:caf_security/tokens
 * @alias similar
 */
exports.similar = function(t1, t2, ignoreExpires) {
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
 * Note that `null` represents the empty token, and `null <= t2 for all t2`.
 *
 * @param {tokenType} t1 A token to compare.
 * @param {tokenType} t2 A token to compare.
 * @return {boolean} t1 <= t2
 *
 * @throws {Error} Malformed token.
 *
 * @memberof! module:caf_security/tokens
 * @alias lessOrEqual
 */
exports.lessOrEqual = function(t1, t2) {
    assert.equal(typeof t1, 'object', "'t1' not an object");
    assert.equal(typeof t2, 'object', "'t2' not an object");

    return similar(meet(t1, t2), t1);
};

/**
 * Signs a token.
 *
 * @param {tokenType} token Token to sign.
 * @param {Object} privKey Private key for signing.
 *
 * @return {string} A serialized signed token.
 * @throws {Error}  Cannot sign.
 *
 * @memberof! module:caf_security/tokens
 * @alias sign
 */
exports.sign = function(token, privKey) {
    return jwt.sign(token, privKey, {algorithm: SIGNATURE_ALGO});
};

const checkToken = function(token) {
    return !CONSTRAINTS.some(function(x) {
        if (token[x] === undefined) {
            return false;
        } else if (x === EXPIRES_AFTER) {
            return !(typeof token[x] === 'number');
        } else if (typeof token[x] !== 'string') {
            return true;
        } else if (token[x].match(/^[a-z0-9]+$/) === null) {
            // ASCII lower characters and numbers only
            return true;
        } else {
            return false;
        }
    });
};

const validUsername =
/**
 *  Checks whether a username contains only valid characters (lower case letters
 * and numbers, ASCII only), and it has at least three characters.
 *
 * @param {string} username A username to check.
 * @return {boolean} True if ok, false otherwise.
 *
 * @memberof! module:caf_security/tokens
 * @alias validUsername
 */
exports.validUsername = function(username) {
    return (typeof username === 'string') && (username.length > 2) &&
        (username.match(/^[a-z0-9]+$/) !== null);
};

/**
 *  Checks whether a username is an extended NOBODY user.
 *
 *  This user can have many CAs as long as their names have only two characters.
 *
 * @param {string} from A full name, e.g., `foo-bar`, to check.
 * @return {boolean} True if ok, false otherwise.
 *
 * @memberof! module:caf_security/tokens
 * @alias validExtendedNobody
 */
exports.validExtendedNobody = function(from) {
    try {
        const ca = json_rpc.splitName(from);
        return (ca.length === 2) &&
            (ca[0] === json_rpc.DEFAULT_FROM_USERNAME) &&
            (ca[1].length === json_rpc.ACCOUNTS_CA_LENGTH) && // avoid DoS
            (validUsername(ca[1]));
    } catch (err) {
        // Not properly formed name
        return false;
    }
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
 * @return{tokenType} A decoded valid token.
 *
 * @throws {Error} Token does not validate
 *
 * @memberof! module:caf_security/tokens
 * @alias validate
 */
exports.validate = function(tokenStr, pubKey) {
    const token = /** @type tokenType*/ (jwt.verify(tokenStr, pubKey));
    if (!checkToken(token)) {
        const err = new Error('Malformed token');
        err['token'] = token;
        throw err;
    }
    if (typeof token[EXPIRES_AFTER] === 'number') {
        if (Date.now() > token[EXPIRES_AFTER]) {
            const error = new Error('Expired token');
            error['token'] = token;
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
 * @return {tokenType} An untrusted token that has NOT been validated.
 *
 * @memberof! module:caf_security/tokens
 * @alias decode
 */
exports.decode = function(tokenStr) {
    return /** @type tokenType*/ (jwt.decode(tokenStr));
};


/**
 * Checks whether a valid token satisfies an ACL (Access control List).
 *
 * Inefficient with many ACLs. See {@link module:caf_security/rules} for a
 * recommended alternative.
 *
 *
 * @param {Array.<tokenType>| tokenType} acl An ACL formed with one or an array
 *  of constraints using a token format.
 * @param {tokenType} token A previously validated token to check 'acl'.
 *
 * @return {boolean} True if satisfies at least one element of the ACL.
 *
 * @memberof! module:caf_security/tokens
 * @alias satisfyACL
 */
exports.satisfyACL = function(acl, token) {
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
 * The type of tokenType is
 *
 *      {appPublisher: string=, appLocalName:string=,
 *       caOwner: string=, caLocalName: string=, expiresAfter: number=}
 *
 *  @param {string=} appPublisher Publisher of the app hosting CAs.
 * @param {string=} appLocalName Name of the app in the 'appPublisher' context.
 * @param {string=} caOwner  Owner of the CA.
 * @param {string=} caLocalName Name of the CA in the owner's context.
 * @param {number=} durationInSec Time in seconds from 'now' till token expires.
 *
 * @return {tokenType} A token or acl element payload.
 *
 * @throws {Error} when input is malformed.
 *
 * @memberof! module:caf_security/tokens
 * @alias newPayload
 */
exports.newPayload = function(appPublisher, appLocalName, caOwner, caLocalName,
                              durationInSec) {
    const result = {};

    const checkAndSetArg = function(arg, argName) {
        if (arg) {
            assert.ok(typeof arg === 'string',
                      "'" + argName + "' is not a string");
            assert.ok(arg.match(/^[a-z0-9]+$/) !== null,
                      "'" + argName + "'  has invalid characters:" + arg);
            result[argName] = arg;
        }
    };

    checkAndSetArg(appPublisher, 'appPublisher');
    checkAndSetArg(appLocalName, 'appLocalName');
    checkAndSetArg(caOwner, 'caOwner');
    checkAndSetArg(caLocalName, 'caLocalName');

    durationInSec && assert.ok(typeof durationInSec === 'number',
                               "'durationInSec' is not a number");
    (typeof durationInSec === 'number') &&
        assert.ok(durationInSec > 0, "'durationInSec' is not positive");

    if (durationInSec) {
        result.expiresAfter = Date.now() + 1000*durationInSec;
    }

    return result;
};
