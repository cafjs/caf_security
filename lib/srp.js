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
 * a risky business.
 *
 * Why SRP then?  Many cloud  deployments terminate TLS early, and SRP provides
 *  an extra level of security when client code is trusted (e.g., node.js
 *  client or native app), and we are login in to an existing account.
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
 *       token = Decrypt(K, Y.token);
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
var assert = require('assert');
var tokens = require('./tokens');
var srpUtils = exports.utils = require('./srpUtils');

exports.clientInstance = require('./srpClient').clientInstance;


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

        if (state[user.username]) {
            username = user.username;
            var verifier = srpUtils.hexToBuf(state[username].verifierHex);
            var secret = srpUtils.newSecret();
            server = new srp.Server(srpUtils.PARAMS, verifier, secret);
            var valueB = server.computeB();

            return {saltHex: state[username].saltHex,
                    valueBHex: srpUtils.bufToHex(valueB)};
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
    that.newToken = function(challenge, tokenConstr) {
        var valueA = srpUtils.hexToBuf(challenge.valueAHex);
        var m1 = srpUtils.hexToBuf(challenge.valueM1Hex);
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
        return { tokenEnc : srpUtils.encryptToken(sharedKey, signedTokenStr),
                 pubKeyHex : srpUtils.bufToHex(pubKey)};
    };

    return that;
};

