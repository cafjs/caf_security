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
 * Security plug for authentication.
 *
 * It is all in the name. We use local namespaces that can be globally
 * identified by using the 'owner' of the namespace. Owners are represented by a
 * globally unique name (or at least unique in our authentication  domain) that
 * we can authenticate. For example, the hash of a public key, or a username in
 * our 'accounts' service.
 *
 * The name of any resource is always prefixed by the 'owner', followed by the
 *  special character '-'. We sometimes use resource names as hostnames and,
 *   (see RFC 1123) we need to restrict characters to ASCII letters and
 *  numbers.
 *
 * When we use public keys instead of usernames, the public key fingerprints
 * are similar to 'ssh-keygen -l' (MD5, hex) but with no semicolon separator,
 * for example:
 *
 *          d41d8cd98a00b204e9700988ecf8427e-myResourceName
 *
 * Using this strategy we name applications as:
 *
 *          appPublisher-appLocalName
 *
 * and a CA in that application as:
 *
 *          caOwner-caLocalName
 *
 * where we assume there is only one `caOwner-caLocalName` within an
 * application, but other applications could reuse it, and therefore, we
 * need to qualify a CA name with its app name to make it globally unique.
 *
 * Authentication is used to create a secure link between the
 * client and its CA in the cloud. We use JSON tokens to weaken
 * authentication, so that we can avoid  impersonation attacks by less trusted
 * apps.  See comments in 'tokens.js' for details.
 *
 *
 * @name caf_security/plug_security
 * @namespace
 * @augments gen_plug
 *
 */
var assert = require('assert');
var url = require('url');
var path = require('path');
var fs = require('fs');
var caf_comp = require('caf_components');
var async = caf_comp.async;
var myUtils = caf_comp.myUtils;
var genPlug = caf_comp.gen_plug;
var json_rpc = require('caf_transport').json_rpc;
var tokens = require('./tokens');
var secUtils = require('./utils');

var MIN_DURATION_SEC = 0.01; // Safety margin before token expires

/**
 * Factory method to create a security plug.
 *
 * @see caf_components/supervisor
 */
exports.newInstance = function($, spec, cb) {

    try {
        var that = genPlug.constructor($, spec);

        $._.$.log && $._.$.log.debug('New security plug');

        var keysDir = spec.env.keysDir || $.loader.__ca_firstModulePath__();

        var loadKey = function(fileName) {
            if (fileName) {
                return fs.readFileSync(path.resolve(keysDir, fileName));
            } else {
                return null;
            }
        };

        var accounts;

        var trustedPubKeyFile =  spec.env.trustedPubKeyFile;
        assert.equal(typeof spec.env.trustedPubKeyFile, 'string',
                     "'spec.env.trustedPubKeyFile' is not a string");
        var trustedPubKey = loadKey(trustedPubKeyFile);

        var privateKey = loadKey(spec.env.privateKeyFile);    // optional
        var publicKey =  loadKey(spec.env.publicKeyFile);    // optional

        spec.env.accountsURL &&
            assert.equal(typeof spec.env.accountsURL, 'string',
                         "'spec.env.accountsURL' is not a string");


        var allowNobodyUser = spec.env.allowNobodyUser;
        assert.equal(typeof spec.env.allowNobodyUser, 'boolean',
                     "'spec.env.allowNobodyUser' is not a boolean");


        var tokenCache = {};

        /**
         * Gets the application name, e.g., `root-helloworld`.
         *
         * @return {string} The application name.
         * @name  caf_security/__ca_getAppName__
         * @function
         */
        that.__ca_getAppName__ = function() {
            return $._.__ca_getAppName__();
        };

        var split = json_rpc.splitName(that.__ca_getAppName__());
        assert.equal(split.length, 2, 'Invalid application name');

        var onlyBasicChars = /^[A-Za-z0-9]*$/;

        var appPublisher = split[0];
        assert.ok(appPublisher && onlyBasicChars.test(appPublisher),
                  "'appPublisher' has non-alphanum characters or is empty:" +
                  appPublisher);

        var appLocalName = split[1];
        assert.ok(appLocalName && onlyBasicChars.test(appLocalName),
                  "'appLocalName' has non-alphanum characters or is empty:" +
                  appLocalName);

        /**
         * Cleans up token caches.
         *
         * Called by `cron_security` periodically to force token re-validation.
         *
         * @name  caf_security/__ca_pulse__
         * @function
         */
        that.__ca_pulse__ = function(cb0) {
            // force re-validation of tokens so that they can expire.
            tokenCache = {};
            cb0(null);
        };

        /*
         * 'null' means cached  with a negative result (invalid token),
         * undefined means not in the cache,
         * otherwise you get the validated token
         *
         */
        var verifyToken = function(tokenStr) {
            if (typeof tokenStr !== 'string') {
                return null;
            }
            var token = tokenCache[tokenStr];
            if (token !== undefined) {
                return token;
            } else {
                try {
                    token = tokens.validate(tokenStr, trustedPubKey);
                    tokenCache[tokenStr] = token;
                    return token;
                } catch (err) {
                    // did not validate, cache negative result.
                    tokenCache[tokenStr] = null;
                    return null;
                }
            }
        };

        var verifyConstraints = function(from, token) {
            try {
                var ca = json_rpc.splitName(from);
                var target = tokens.newPayload(appPublisher, appLocalName,
                                               ca[0], ca[1], MIN_DURATION_SEC);
                return tokens.lessOrEqual(target, token);
            } catch (err) {
                 $._.$.log && $._.$.log.debug('Exception testing constraints' +
                                              myUtils.errToPrettyStr(err));
                return false;
            }
        };

        /**
         * Verifies the provided serialized token is trusted
         *
         * @param {string} tokenStr A serialized token to validate.
         *
         * @return {caf.token|null} A parsed, validated token, or `null` if
         * token invalid.
         *
         * @name  caf_security/__ca_verifyToken__
         * @function
         */
        that.__ca_verifyToken__ = function(tokenStr) {
            return verifyToken(tokenStr);
        };

        /**
         * Authenticates the incoming request.
         *
         * @param {string} from Principal sending this request.
         * @param {string} tokenStr Token to authenticate the principal.
         * @param {caf.cb} cb0 A callback with an error or the authenticated
         *  token.
         *
         * @name  caf_security/__ca_authenticate__
         * @function
         */
        that.__ca_authenticate__ = function(from, tokenStr, cb0) {
            var sorry = function(info) {
                var err = new Error(info);
                err.from = from;
                err.tokenStr = tokenStr;
                err.accountsURL = spec.env.accountsURL;
                return err;
            };

            if (typeof from === 'string') {
                if (allowNobodyUser && (json_rpc.DEFAULT_FROM === from)) {
                    // bypass authentication
                    cb0(null);
                } else if (typeof tokenStr === 'string') {
                    var token = verifyToken(tokenStr);
                    if (!token) {
                        cb0(sorry('Invalid Token'));
                    } else if (!verifyConstraints(from, token)) {
                        cb0(sorry('Token does not respect constraints'));
                    } else {
                        // all checks clear
                        cb0(null, token);
                    }
                } else {
                    cb0(sorry( "Missing 'token' field"));
                }
            } else {
                cb0(sorry( "Missing 'from' field"));
            }
        };

        /**
         * Whether we should block attempts to create a new CA if missing.
         *
         * Only the owner should be allowed to create new CAs.
         *
         * @param {string} from Source of the request.
         * @param {string} to Target CA to be created if missing.
         * @return {boolean} True if we should only allow returning a reference
         *  to an existing CA.
         *
         */
        that.__ca_blockCreate__ = function(from, to) {
            if (from !== to) {
                // only the owner can create a CA.
                $._.$.log && $._.$.log.warn('Blocking create of ' + to +
                                            ' by ' + from);
                return true;
            } else {
                return false;
            }
        };

        var remoteAttenuateToken = function(megaTokenStr, constraints, cb0) {
            try {
                var closeF = function(err) {
                    accounts = null;
                    if (err) {
                        $._.$.log &&
                            $._.$.log.warn('Accounts session error' +
                                           myUtils.errToPrettyStr(err));
                    };
                };
                var cb1 = function(err, acc) {
                    if (err) {
                        cb0(err);
                    } else {
                        accounts = acc;
                        accounts.attenuateToken(megaTokenStr, constraints, cb0);
                    }
                };
                secUtils.accountsSession(accounts, spec.env.accountsURL,
                                         closeF, cb1);
            } catch(err) {
                cb0(err);
            }
        };

        var attenuateOneToken = function(megaTokenStr, constraints, cb0) {
            try {
                var ifNull = function(mega, constr, propName) {
                    return (constr[propName] === null ? mega[propName] :
                            constr[propName]);
                };
                var megaToken = tokens.validate(megaTokenStr, trustedPubKey);
                var target = tokens
                    .newPayload(ifNull(megaToken, constraints, 'appPublisher'),
                                ifNull(megaToken, constraints, 'appLocalName'),
                                ifNull(megaToken, constraints, 'caOwner'),
                                ifNull(megaToken, constraints, 'caLocalName'),
                                constraints.durationInSec);

                if (tokens.lessOrEqual(target, megaToken)) {
                    var signedToken = tokens.sign(target, privateKey);
                    tokens.validate(signedToken, publicKey);
                    cb0(null, signedToken);
                } else {
                    var err = new Error('Token is not weaker');
                    err.megaToken = megaToken;
                    err.constraints = constraints;
                    throw err;
                }
            } catch(err) {
                cb0(err);
            }
        };

        that.__ca_attenuateToken__ = function(megaTokenStr, constraints, cb0) {
            if (privateKey) {
                if (Array.isArray(constraints)) {
                    async.map(constraints, function(one, cb1) {
                                  attenuateOneToken(megaTokenStr, one, cb1);
                              }, cb0);
                } else {
                    attenuateOneToken(megaTokenStr, constraints, cb0);
                }
            } else {
                remoteAttenuateToken(megaTokenStr, constraints, cb0);
            }
        };

        cb(null, that);
    } catch (err) {
        cb(err);
    }
};
