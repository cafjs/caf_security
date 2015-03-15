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
 * Utility methods to implement an SRP-based password authentication protocol.
 *
 * SRP derives a strong shared secret from a weak one (i.e., a password) using
 * a zero-knowledge technique, and then the server uses the strong secret to
 * encrypt the token.
 *
 *                            WARNING!!!!
 *                            -----------
 * We still need TLS to create accounts, and to avoid a browser-based client to
 * download a tainted 'srp' implementation. Javascript crypto in the browser is
 * a risky business. However, SRP provides an extra level of security when
 * client code is trusted (e.g., node.js client or native app), and we are
 * login in to an existing account, because many cloud  deployments terminate
 * TLS early.
 *
 * The protocol, loosely based on RFC 5054, is as follows:
 *
 *     Client                           Server
 *     ------                           ------
 *     *Client 'hello'* {username}         ->     *Server 'hello'*
 *
 *     *Client 'login'*                  <-   X = {salt: salt, B: ComputeB() }
 *
 *     A = ComputeA(passwd, username, X.salt)
 *     M1 = ComputeM1(X.B) // challenge value
 *
 *     {A, tokenConstr, M1}             ->   *Server 'newToken'*
 *
 *                                            ok = checkM1(A, M1);
 *                                            if (ok) {
 *                                              K = computeK() // shared secret
 *                                              token = newToken(tokenConstr)
 *                                              tkEnc = Encrypt(K, token);
 *                                            } else {
 *                                              tkEnc = null;
 *                                            }
 *
 *     *Client 'newToken'*               <- Y = {tokenEnc: tkEnc}
 *
 *    if (Y.tokenEnc != null) {
 *       K = computeK();
 *       token = Decript(K, Y.token);
 *       ok = validateToken(token, tokenConstr)
 *       if (ok) {
 *           return token
 *       } else {
 *          // login error
 *       }
 *    } else {
 *      // bad password or username or token constraints.
 *    }
 *
 *
 * And to create a new account:
 *
 *
 *    *Client NewAccount*
 *
 *     salt = computeSalt()
 *     verifier = computeVerifier(username, salt, passwd)
 *
 *     {verifier, salt, username}    ->          *Server NewAccount*
 *
 *                                                ok = validUsername(username)
 *                                                ok && registerUser(...)
 *            ....                   <-           ok
 *
 *
 *
 *
 * @name caf_security/srp
 * @namespace
 */



var srp = require('srp');
var crypto = require('crypto');
var assert = require('assert');
var tokens = require('./tokens');

var NUM_BITS = "2048";
var SALT_BYTES = 32;
var KEY_BYTES = 32;
var PARAMS = srp.params[NUM_BITS];

var ENCRYPTION_ALGO = 'AES-256-CTR';


var bufToHex = function(buf) {
    return buf.toString('hex');
};

var hexToBuf = function(hex) {
    return Buffer(hex, 'hex');
};

var newSalt = function() {
    return crypto.randomBytes(SALT_BYTES);
};

var newSecret = function() {
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

var strToBuffer = function(str) {
    return Buffer(str, 'utf8');
};

exports.clientInstance = function(user, passw) {

    var that = {};
    var username = user;
    var password = strToBuffer(passw);
    var client = null;
    var sharedKey = null;

    /**
     * Create verifier and salt for new account.
     *
     */
    that.newAccount = function() {
        var salt = newSalt();
        var verifier = srp.computeVerifier(PARAMS, salt, strToBuffer(username),
                                           password);
        return {username : username, verifierHex: bufToHex(verifier),
                saltHex: bufToHex(salt)};
    };

    /**
     * Initiate a token request.
     *
     * This is Step 1.
     *
     */
    that.hello = function() {
        sharedKey = null;
        client = null;
        return {username : username};
    };

    /**
     *  Process salt and valueB from server. Create shared key and challenge.
     *
     *  This is Step 2.
     *
     */
    that.login = function(saltHex, valueBHex, tokenConstr) {
        var salt = hexToBuf(saltHex);
        var valueB = hexToBuf(valueBHex);
        var secret = newSecret();
        client = new srp.Client(PARAMS, salt, strToBuffer(username),
                                password, secret);
        var valueA = client.computeA();
        client.setB(valueB);
        var M1 = client.computeM1();
        sharedKey = client.computeK();
        return {valueAHex: bufToHex(valueA), valueM1Hex:  bufToHex(M1),
                tokenConstr : tokenConstr};
    };

    /**
     *  Decrypt and validate token from server.
     *
     *  This is Step 3.
     *
     */
    that.newToken = function(tokenEnc, pubKey, tokenConstr) {
        var throwError = function(msg) {
            var err = new Error(msg);
            err.tokenEnc = tokenEnc;
            err.pubKey = pubKey;
            err.tokenConstr = tokenConstr;
            throw err;
        };
        if (!tokenEnc) {
            throwError('null token');
        }
        var tokenStr = decryptToken(sharedKey, tokenEnc);
        var token = tokens.validate(tokenStr, pubKey);
        if (!tokens.similar(token, tokenConstr, true)) {
            throwError('Changed token constraints');
        }
        return tokenStr;
    };

    return that;

};

exports.serverInstance = function(stateAll, prKey, puKey) {

    var that = {};
    var state = stateAll;
    var server = null;
    var privKey = prKey;
    var pubKey = puKey;
    var sharedKey = null;
    var username;

    /**
     * Register verifier and salt for new account.
     *
     */
    that.newAccount = function(account) {
        var throwError = function(msg) {
            var err = new Error(msg);
            err.username = account.username;
            throw err;
        };
        if (!tokens.validUsername(account.username)) {
            throwError('Invalid username');
        } else if (state[account.username]) {
            throwError('Username already in use.');
        } else {
            assert.equal(typeof account.verifierHex, 'string');
            assert.equal(typeof account.saltHex, 'string');
            var newAccount = {verifierHex : account.verifierHex,
                              saltHex : account.saltHex};
            state[account.username] = newAccount;
            return newAccount;
        }
    };

    /**
     * Initiate a token request (server).
     *
     * This is Step 1.
     *
     */
    that.hello =  function(user) {
        server = null;
        sharedKey = null;
        username  = null;

        if (state[user]) {
            username = user;
            var verifier = hexToBuf(state[username].verifierHex);
            var secret = newSecret();
            server = new srp.Server(PARAMS, verifier, secret);
            var valueB = server.computeB();

            return {saltHex: state[username].saltHex,
                    valueBHex: bufToHex(valueB)};
        } else {
            var err = new Error('Invalid username');
            err.username = account.username;
            throw err;
        }
    };

    /**
     * Creates an encrypted token after authentication.
     *
     * This is Step 2.
     *
     */
    that.newToken = function(valueAHex, valueM1Hex, tokenConstr) {
        var valueA = hexToBuf(valueAHex);
        var m1 = hexToBuf(valueM1Hex);
        server.setA(valueA);
        server.checkM1(m1);
        sharedKey = server.computeK();
        assert.equal(typeof username, 'string');
        assert.equal(username, tokenConstr.caOwner);
        var p = tokens.newPayload(tokenConstr.appPublisher,
                                  tokenConstr.appLocalName,
                                  tokenConstr.caOwner, tokenConstr.caLocalName,
                                  tokenConstr.durationInMsec);
        var signedTokenStr = tokens.sign(p, privKey);
        tokens.validate(signedTokenStr, pubKey);
        return { tokenEnc : encryptToken(sharedKey, signedTokenStr)};
    };

    return that;
};

