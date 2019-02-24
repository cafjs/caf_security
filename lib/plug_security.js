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
/**
 * Security plug for authentication.
 *
 * Properties:
 *
 *       {keysDir: string=, trustedPubKeyFile: string, privateKeyFile: string=,
 *        publicKeyFile: string=, accountsURL: string, allowNobodyUser: boolean,
 *        quotaURL: string=, quotaCA: string=}
 *
 * where:
 *
 * * `keysDir:` directory for all key material.
 * * `trustedPubKeyFile`: trusted public key that verifies tokens. Uses
 * a self-signed certificate in PEM format, see `openssl`.
 * * `privateKeyFile` and `publicKeyFile`: optional asymetric keys to weaken
 * tokens. Typically we use a remote service instead.
 * * `accountsURL`: URL of the accounts service.
 * * `allowNobodyUser`: whether to allow the `json_rpc.DEFAULT_FROM` client to
 * authenticate without credentials.
 * * `quotaURL`: the URL of the quota service, or missing if service off.
 * * `quotaCA`: the CA entrypoint for the service, or missing if service off.
 *
 *
 * @module caf_security/plug_security
 * @augments external:caf_components/gen_plug
 *
 */
// @ts-ignore: augments not attached to a class
var assert = require('assert');
var path = require('path');
var fs = require('fs');
var caf_comp = require('caf_components');
var async = caf_comp.async;
var myUtils = caf_comp.myUtils;
var genPlug = caf_comp.gen_plug;
var json_rpc = require('caf_transport').json_rpc;
var tokens = require('./tokens');
var secUtils = require('./utils');
var cli = require('caf_cli');

var MIN_DURATION_SEC = 0.01; // Safety margin before token expires

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

        var trustedPubKeyFile = spec.env.trustedPubKeyFile;
        assert.equal(typeof spec.env.trustedPubKeyFile, 'string',
                     "'spec.env.trustedPubKeyFile' is not a string");
        var trustedPubKey = loadKey(trustedPubKeyFile);

        var privateKey = loadKey(spec.env.privateKeyFile);    // optional
        var publicKey = loadKey(spec.env.publicKeyFile); // optional

        spec.env.accountsURL &&
            assert.equal(typeof spec.env.accountsURL, 'string',
                         "'spec.env.accountsURL' is not a string");


        var allowNobodyUser = spec.env.allowNobodyUser;
        assert.equal(typeof spec.env.allowNobodyUser, 'boolean',
                     "'spec.env.allowNobodyUser' is not a boolean");

        spec.env.quotaURL &&
            assert.equal(typeof spec.env.quotaURL, 'string',
                         "'spec.env.quotaURL' is not a string");

        spec.env.quotaCA &&
            assert.equal(typeof spec.env.quotaCA, 'string',
                         "'spec.env.quotaCA' is not a string");

        var tokenCache = {};

        that.__ca_getAppName__ = function() {
            return $._.__ca_getAppName__();
        };

        var split = json_rpc.splitName(that.__ca_getAppName__());
        assert.equal(split.length, 2, 'Invalid application name ' +
                     that.__ca_getAppName__());

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
         * @param {cbType} cb0 A callback to continue after cleaning.
         *
         * @memberof! module:caf_security/plug_security#
         * @alias __ca_pulse__
         */
        that.__ca_pulse__ = function(cb0) {
            // force re-validation of tokens so that they can expire.
            tokenCache = {};
            cb0(null);
        };

        /*
         * `null` means cached  with a negative result (invalid token),
         * `undefined` means not in the cache,
         * otherwise you get the validated token.
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
                assert.ok(ca.length === 2, 'Invalid name');
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
         * @return {tokenType|null} A parsed, validated token, or `null` if
         * token invalid.
         *
         * @memberof! module:caf_security/plug_security#
         * @alias __ca_verifyToken__
         */
        that.__ca_verifyToken__ = function(tokenStr) {
            return verifyToken(tokenStr);
        };

        /**
         * Authenticates the incoming request.
         *
         * @param {string} from Principal sending this request.
         * @param {string} tokenStr Token to authenticate the principal.
         * @param {cbType} cb0 A callback with an error or the authenticated
         *  token.
         *
         * @memberof! module:caf_security/plug_security#
         * @alias __ca_authenticate__
         */
        that.__ca_authenticate__ = function(from, tokenStr, cb0) {
            var sorry = function(info) {
                var err = new Error(info);
                err['from'] = from;
                err['tokenStr'] = tokenStr;
                err['accountsURL'] = spec.env.accountsURL;
                $._.$.log && $._.$.log.debug('Deny: ' + info +
                                             JSON.stringify(err));
                return err;
            };

            var isNobodyUser = function() {
                return (json_rpc.DEFAULT_FROM === from) ||
                    tokens.validExtendedNobody(from);
            };

            if (typeof from === 'string') {
                if (allowNobodyUser && isNobodyUser()) {
                    // bypass authentication
                    cb0(null);
                } else if (typeof tokenStr === 'string') {
                    var token = verifyToken(tokenStr);
                    if (!token) {
                        $._.$.log && $._.$.log.debug('Invalid Token:' +
                                                     tokenStr.slice(0, 20));
                        cb0(sorry('Invalid Token'));
                    } else if (!verifyConstraints(from, token)) {
                        var msg = 'Token does not respect constraints';
                        $._.$.log && $._.$.log.debug(msg + ' from: ' + from +
                                                     ' token:' +
                                                     JSON.stringify(token));
                        cb0(sorry(msg));
                    } else {
                        // all checks clear
                        cb0(null, token);
                    }
                } else {
                    $._.$.log && $._.$.log.debug('Missing token');
                    cb0(sorry("Missing 'token' field"));
                }
            } else {
                cb0(sorry("Missing 'from' field"));
            }
        };

        /**
         * Whether we should block attempts to create a missing CA.
         *
         * Only the owner should be allowed to create new CAs, i.e.,
         * `from === to`.
         *
         * @param {string} from Source of the request.
         * @param {string} to Target CA to be created if missing.
         * @return {boolean} True if we should only allow returning a reference
         *  to an existing CA.
         *
         * @memberof! module:caf_security/plug_security#
         * @alias __ca_blockCreate__
         */
        that.__ca_blockCreate__ = function(from, to) {
            if (from !== to) {
                // only the owner can create a CA.
                $._.$.log && $._.$.log.trace('Blocking create of ' + to +
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
                    }
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
                                         constraints['caOwner'], closeF, cb1);
            } catch (err) {
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
                    err['megaToken'] = megaToken;
                    err['constraints'] = constraints;
                    throw err;
                }
            } catch (err) {
                cb0(err);
            }
        };

        /**
         * Weakens an authentication token generating generating one (or many)
         *  token(s).
         *
         * @see {@link module:caf_security/proxy_security#attenuateToken}
         *
         *
         * @param {string} megaTokenStr A serialized token.
         * @param {tkDescArray} constraints A description of the new token(s).
         * @param {cbType} cb0 A callback to return the new token(s) or an
         *  error.
         *
         * @memberof! module:caf_security/plug_security#
         * @alias __ca_attenuateToken__
         */
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

        var callCrossApp = async function(fqn, method, args, cb0) {
            try {
                var res = await $._.$.crossapp.call(fqn, json_rpc.DEFAULT_FROM,
                                                    method, args);
                if (res[0]) {
                    // system error defaults to `Internal Error`
                    res[0].quotaExceeded = !(res[0].isSystemError);
                    cb0(res[0]);
                } else {
                    cb0(null, res[1]);
                }
            } catch (err) {
                cb0(err); //bad inputs, programming error
            }
        };

        var toFQN = function(owner) {
            return json_rpc.joinNameArray([
                spec.env.quotaApp,
                json_rpc.joinName(owner, json_rpc.DEFAULT_QUOTA_ID)
            ], json_rpc.APP_SEPARATOR);
        };

        /**
         * Registers a new CA with the *Quota* service.
         *
         * @param {string} tokenStr An encoded token. This token was originally
         * used to create the CA.
         * @param {cbType} cb0 A callback to return an error, or extra CA info
         * (second argument).  If the error is not a system error, i.e., we
         * accessed the quota service and there was no balance, the error field
         * `quotaExceeded` is set to `true`.
         *
         * @memberof! module:caf_security/plug_security#
         * @alias __ca_quotaRenew__
         */
        that.__ca_quotaRenew__ = function(tokenStr, cb0) {
            if (spec.env.quotaApp) {
                var token = that.__ca_verifyToken__(tokenStr);
                if (token) {
                    var fqn = toFQN(token.caOwner);
                    callCrossApp(fqn, 'registerCA', [tokenStr], cb0);
                } else {
                    cb0(new Error('Invalid token'));
                }
            } else {
                cb0(null, 'Skip quota renew');
            }
        };

        /**
         * Checks the quota of a CA with the *Quota* service.
         *
         * @param {string} caId A target CA identifier, e.g., `foo-ca1`.
         * @param {cbType} cb0 A callback to return an error, or extra CA info
         * (second argument).  If the error is not a system error, i.e., we
         * accessed the quota service and there was no balance, the error field
         * `quotaExceeded` is set to `true`.
         *
         * @memberof! module:caf_security/plug_security#
         * @alias __ca_quotaCheck__
         */
        that.__ca_quotaCheck__ = function(caId, cb0) {
            if (spec.env.quotaApp) {
                var splitName = json_rpc.splitName(caId);
                if (splitName.length !== 2) {
                    var fqn = toFQN(splitName[0]);
                    callCrossApp(fqn, 'checkCA', [caId], cb0);
                } else {
                    cb0(new Error('Invalid CA identifier'));
                }
            } else {
                cb0(null, 'Skip quota check');
            }
        };

        cb(null, that);
    } catch (err) {
        cb(err);
    }
};
