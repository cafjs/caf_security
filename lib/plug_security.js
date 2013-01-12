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
 * Security plug for authentication based on Passport.
 *
 * A CA is identified by a tuple `appName_caName` where the
 * appName is composed of `appPublisher_appLocalName` and
 * the caName of `caOwner_caLocalName`.
 *
 * Both appPublisher and caOwner represent principals that, respectively,
 * wrote/deployed the app or own an instance of that app (i.e., a running CA).
 * Principals are authenticated by the framework  using an external service
 * like 'accounts' and are assumed globally unique.
 *
 * Note that strings appPublisher and caOwner cannot
 * contain special characters #, $, | or _ . We also reserve 'root',
 * the default when appPublisher is missing, and represents an app provided
 * by the platform owner.
 *
 *
 *  Both appLocalName and caLocalName are anything its owner wants but they
 * should be unique in their local context.
 *
 * Authentication is used to create a secure link between the
 * (browser) app and its CA in the cloud. We use tokens to limit
 * authentication so that we can use a less trusted
 * app and still avoid  impersonation attacks. Constraints are based on
 * appName#caName.  See comments in util_security for details.
 *
 *
 * It should be defined in framework.json with name 'security_mux'.
 *
 * @name caf_security/plug_security
 * @namespace
 * @augments gen_plug
 *
 */
var crypto = require('crypto');
var caf = require('caf_core');
var genPlug = caf.gen_plug;
var json_rpc = caf.json_rpc;
var Passport = require('passport').Passport;
var basicStrategy = require('./BasicCAStrategy');
var sec_util = require('./util_security');
var url = require('url');
var util_accounts = require('./util_accounts');

/**
 * Factory method to create a security plug.
 */
exports.newInstance = function(context, spec, secrets, cb) {


    var that = genPlug.constructor(spec, secrets);
    var $ = context;

    var keysDir = $.loader && $.loader.getPath();

    var strategy = (spec.env && spec.env.strategy) ||
        {local: {
             tokenKey: 'pleasechange',
             tokenExpires: 1000000000000000,
             users: {}
         },
         accounts: {
             serviceName: 'accounts',
             serviceUrl: null,
             pubFile: 'rsa_pub.pem',
             keysDir: keysDir,
             unrestricted: false,
             disabled: false // for debugging enable local
         }
        };

    // local service
    // users are {name : hashedPassword{string}}
    var users = (strategy.local && strategy.local.users) || {};
    var tokenKey = (strategy.local && strategy.local.tokenKey) ||
        'pleasechange';
    var tokenExpires = (strategy.local && strategy.local.tokenExpires) ||
        1000000000000000;

    // accounts service
    var serviceName = (strategy.accounts && strategy.accounts.serviceName) ||
        'accounts';
    var serviceUrl = (strategy.accounts && strategy.accounts.serviceUrl) ||
        null;
    var pubFile = (strategy.accounts && strategy.accounts.pubFile) ||
        'rsa_pub.pem';
    keysDir = (strategy.accounts && strategy.accounts.keysDir) || keysDir;
    var unrestricted = (strategy.accounts && strategy.accounts.unrestricted) ||
        false;
    var accountsDisabled = (strategy.accounts && strategy.accounts.disabled) ||
        false;
    var pubKey = null;
    // cached appPublisher and appLocalName for this app
    var appCon = null;


    var passport = new Passport();
    var tokenCache = {};

    /**
     * Cleans up token caches.
     *
     * Called by `cron_security` periodically to force token re-validation.
     *
     * @name  caf_security/pulse
     * @function
     */
    that.pulse = function(cb0) {
        // force re-validation of tokens
        tokenCache = {};
        cb0(null);
    };

    var newToken = function(caOwner) {
        var expires = (new Date()).valueOf() + 1000 * tokenExpires;
        var tk = sec_util.newToken(undefined, undefined, caOwner, undefined,
                                   expires);
        return sec_util.signToken(tokenKey, tokenKey, 'HMAC-SHA1', tk);
    };

    /*
     * null means cached  negative result (invalid token)
     * undefined means not in the cache
     * otherwise you get the authenticated caOwner
     *
     * Cache gets flushed periodically to take 'expires' into
     * account.
     *
     */
    var verifyToken = function(token) {
        if (!token) {
            return null;
        }
        var tokenStr = JSON.stringify(token);
        var user = tokenCache[tokenStr];
        if (user !== undefined) {
            return user;
        } else {
            var key = token.algo &&
                (token.algo === 'HMAC-SHA1' ? tokenKey : pubKey);
            if (key && sec_util.validateSignedToken(key, token)) {
                user = token.caOwner;
                tokenCache[tokenStr] = user;
                return user;
            }
            tokenCache[tokenStr] = null;
            return null;
        }
    };


    var verifyConstraints = function(token, req) {
        if (!appCon) {
            /* SECURITY WARNING:
             *
             * We are relying on an unauthenticated http header to
             * chose a name for this app. Luckily, since we only use the
             * host field, and Cloud Foundry relies on that field to route
             *  http traffic, we should be fine.
             *
             *  However, if we implement a network bypass we should specify
             *  the appName in the config file.
             *
             */
            appCon = sec_util.hostnameToConstraints(req.headers.host);
        }
        var caName = $.pipe.caIdFromUrl(req.originalUrl);
        var caOwner = $.pipe.ownerFromCaId(caName);
        var caLocalName = $.pipe.caLocalNameFromCaId(caName);
        var conToken = sec_util.newToken(appCon.appPublisher,
                                         appCon.appLocalName,
                                         caOwner, caLocalName);
        return sec_util.lessOrEqual(conToken, token);
    };

    /*
     * Configures connect middleware and passport
     */
    that.useConfig = function(app) {
        passport.use('local',
                     new basicStrategy.Strategy(basicStrategy.handler(users)));
        app.use(passport.initialize());
    };


    var findServiceUrl = function(reqUrl, service) {
        var parsedUrl = url.parse(reqUrl);
        var host = parsedUrl.host.split('.');
        host.shift();
        host.unshift(service);
        parsedUrl.host = host.join('.');
        delete parsedUrl.path;
        parsedUrl.pathname = '/app.html';
        delete parsedUrl.search;
        delete parsedUrl.query;
        return url.format(parsedUrl);
    };

    var headless = function(h) {
        var res = h.split('.');
        res.shift();
        return res.join('.');
    };
    var patchServiceUrl = function(accUrl, appHost, appPathUrl) {
        var caName = $.pipe.caIdFromUrl(appPathUrl);
        var caOwner = $.pipe.ownerFromCaId(caName);
        var caLocalName = $.pipe.caLocalNameFromCaId(caName);
        var parsedUrl = url.parse(accUrl, true);
        if (headless(parsedUrl.host) !== headless(appHost)) {
            $.log && $.log.warn('Cross-domain account request: ' +
                                'accountsURL:' + accUrl + ' host:' + appHost);
        }
        var goToUrl = url.parse(accUrl, true);
        goToUrl.host = appHost;
        parsedUrl.query = {goTo: url.format(goToUrl),
                           caLocalName: caLocalName,
                           caOwner: caOwner,
                           unrestrictedToken: unrestricted};
        return url.format(parsedUrl);
    };

    var sorry = function(req, res, info) {
        if (strategy.accounts && !serviceUrl) {
            /* WARNING: THIS IS INSECURE
             *
             * We are relying on an unauthenticated http header to
             * chose a candidate domain for the 'accounts' service.
             * This could allow re-direction to a 'fake' accounts service
             * that collects passwords.
             *
             *  In production we should specify the service url in the config
             *  file (framework.json).
             *
             */
            serviceUrl = findServiceUrl(req.headers.origin + req.originalUrl,
                                        serviceName);
        }
        var accountsURL = (accountsDisabled ? undefined :
                           (strategy.accounts ?
                            patchServiceUrl(serviceUrl, req.headers.host,
                                            req.originalUrl) : undefined)
                          );
        var code = json_rpc.ERROR_CODES.notAuthorized;
        var sysError = json_rpc.systemError(req.body, code,
                                            JSON.stringify(info),
                                            {accountsURL: accountsURL});
        res.send(JSON.stringify(sysError));
    };

    var welcome = function(req, res, user) {
        var token = newToken(user);
        var resp = json_rpc.reply(req.body, null, token);
        res.send(JSON.stringify(resp));
    };

    that.attenuateToken = function(megaToken, constraints, cb0) {
        if (serviceUrl) {
            util_accounts.attenuateToken(serviceUrl, megaToken,
                                         constraints, cb0);
        } else {
            cb0('serviceUrl is null: set serviceUrl to the Accounts' +
                ' service location');
        }
    };


    /*
     * Adds an express route for login
     */
    that.routeConfig = function(app, redirUrl) {
        app.post(redirUrl, function(req, res, next) {
                     var cb1 = function(err, user, info) {
                         if (err) {
                             next(err);
                         } else if (!user) {
                             sorry(req, res, info);
                         } else {
                             welcome(req, res, user);
                         }
                     };
                     passport.authenticate('local', cb1)(req, res, next);
                 });
    };

    /*
     * Returns 'connect' middleware to validate security tokens.
     *
     */
    that.connectSetup = function() {
        return function(req, res, next) {
            var msg = req.body;
            var token = json_rpc.getToken(msg);
            var from = json_rpc.getFrom(msg);
            if (token && from) {
                var user = verifyToken(token);
                if (!user || (user.indexOf('_') !== -1)) {
                    sorry(req, res, 'Invalid Token');
                } else if (from.indexOf(user + '_') !== 0) {
                    sorry(req, res, 'Invalid From field');
                } else if (!verifyConstraints(token, req)) {
                    sorry(req, res, 'Token does not respect constraints');
                } else {
                    // all checks clear
                    next();
                }
            } else {
                sorry(req, res, 'Missing Token or From field');
            }
        };
    };
    var cb0 = function(err, pub) {
        if (err) {
            cb(err);
        } else {
            pubKey = pub;
            cb(null, that);
        }
    };
    if (strategy.accounts) {
        sec_util.loadKey(pubFile, keysDir, cb0);
    } else {
        cb(null, that);
    }
};
