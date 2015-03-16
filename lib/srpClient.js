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
 * @name caf_security/srpClient
 * @namespace
 */
var srp = require('srp');
var srpUtils = require('./srpUtils');
var async = require('async');

exports.clientInstance = function(user, passw) {

    var that = {};
    var username = user;
    var password = srpUtils.strToBuffer(passw);
    var client = null;
    var sharedKey = null;

    /**
     * Create verifier and salt for new account.
     *
     */
    that.newAccount = function() {
        var salt = srpUtils.newSalt();
        var verifier = srp.computeVerifier(srpUtils.PARAMS, salt,
                                           srpUtils.strToBuffer(username),
                                           password);
        return {username : username, verifierHex: srpUtils.bufToHex(verifier),
                saltHex: srpUtils.bufToHex(salt)};
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
    that.login = function(helloServerReply) {
        var salt = srpUtils.hexToBuf(helloServerReply.saltHex);
        var valueB = srpUtils.hexToBuf(helloServerReply.valueBHex);
        var secret = srpUtils.newSecret();
        client = new srp.Client(srpUtils.PARAMS, salt,
                                srpUtils.strToBuffer(username),
                                password, secret);
        var valueA = client.computeA();
        client.setB(valueB);
        var M1 = client.computeM1();
        sharedKey = client.computeK();
        return {valueAHex: srpUtils.bufToHex(valueA),
                valueM1Hex:  srpUtils.bufToHex(M1)};
    };

    /**
     *  Decrypt and validate token from server.
     *
     *  This is Step 3.
     *
     */
    that.newToken = function(tokenBundle, tokenConstr) {
        var tokenEnc = tokenBundle.tokenEnc;
        var throwError = function(msg) {
            var err = new Error(msg);
            err.tokenEnc = tokenEnc;
            err.tokenConstr = tokenConstr;
            throw err;
        };
        if (!tokenEnc) {
            throwError('null token');
        }
        var tokenStr = srpUtils.decryptToken(sharedKey, tokenEnc);
        var token = srpUtils.decodeToken(tokenStr);
        if (!srpUtils.similarTokens(token, tokenConstr, true)) {
            throwError('Changed token constraints');
        }
        return tokenStr;
    };

    /**
     * Drives the client workflow to obtain a token from the server.
     *
     */
    that.asyncToken = function(server, tokenConstr, cb) {
        async.waterfall(
            [
                function(cb0) {
                    server.hello(that.hello(), cb0);
                },
                function(helloServerReply, cb0) {
                    server.newToken(that.login(helloServerReply),
                                    tokenConstr, cb0);
                }
            ], function(err, tokenBundle) {
                if (err) {
                    cb(err);
                } else {
                    try {
                        cb(null, that.newToken(tokenBundle, tokenConstr));
                    } catch (error){
                        cb(error);
                    }
                }

            });
    };

    return that;

};

