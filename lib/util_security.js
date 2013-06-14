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
var passwordHash = require('password-hash');
var crypto = require('crypto');
var path = require('path');
var fs = require('fs');
var url = require('url');


/*
 * Tokens are the primary mechanism to implement constrained delegation
 * in CAF. A token is typically used by the front-end of an app (running in
 * the client device) to create a secure session with its corresponding CA
 * (running in the cloud). A simple way to do that would be to authenticate
 *  with the client's credentials (e.g., username/password). However,
 * we want to create instances of apps (with CAs) implemented by less trusted
 * third parties, and we may not want to share login credentials with them.
 *
 * Instead, we just create and handover a token that can only be used to
 * authenticate the client in a restricted context. For example, for a limited
 * period of time or just for a particular app or just for a particular CA in
 * an app or for all the apps published by certain trusted party...
 *
 * Tokens are just JavaScript (frozen) objects with a property containing a
 * signature but we have a canonical way to serialize
 * them, so that we can compute predictable hashes from them.
 *
 * Most tokens need to be signed with a private key (e.g., RSA) because
 *  a symmetric
 *  key would defeat the purpose of constrained delegation. Private keys are
 * difficult to manage in the client device, specially if we want to change
 * devices while maintaining session context. Instead, we use a service called
 * 'Accounts' that would sign our tokens if we manage to authenticate to it
 * with our login credentials (or a valid, more powerful, token).
 * The public key of 'Accounts' should be configured in all the apps that
 * want to support single sign-on (e.g., file rsa_pub.pem in ./lib directory).
 *
 * Apps that do not support single sign-on will prompt for a password and the
 *  user will decide whether it wants to disclose it (after that a
 * non-constrained token with a symmetric key -just for that app- will be
 * created).
 *
 * The structure of the token is as follows:
 * {algo : <'RSA-SHA256' | 'HMAC-SHA1' >, appPublisher:<string>,
 *  appLocalName:<string>,  caOwner : <string>, caLocalName :<string>,
 * expires :<number>, signature:<string>}
 *
 * where:
 *
 * algo: specifies how it has been signed. Note that HMAC cannot be reliably
 * used outside the scope of an app because it uses symmetric keys.
 *
 * appPublisher: name of whoever published the app. Built-in apps default to
 * 'root'.
 *
 * appLocalName: name of the app in the local context of 'appPublisher'.
 *
 * caOwner: name of whoever is being authenticated (that owns the CA) and
 * we want to constrain its authority.
 *
 * caLocalName: a local name for the CA in the context of 'caOwner'
 *
 * expires: Expire time of token (in milliseconds since midnight January 1,1970)
 *
 * signature:   base64 encoded and derived from signing slgorithm of the
 *  utf-8 string:
 *
 *    CAFTOKENv0.1|algo|appPublisher|appLocalName|caOwner|caLocalName|expires
 *
 * where an optional constraint not present (i.e., appPublisher, appLocalName or
 * caLocalName) is just an empty string, e.g,
 *
 *  CAFTOKENv0.1|algo|||caOwner||expires
 *
 *  gives full authentication of caOwner until 'expires'
 *
 * and CAFTOKENv0.1|algo|'root'||caOwner||expires
 *
 *  can only be used with built-in apps.
 *
 *
 * We can define a partial order of tokens based on the relative strength
 * of the role of caOwner after applying constraints.
 *
 * The ordered set of tokens form a join semi-lattice where
 *  the bottom  is the empty set (i.e., a token that is not valid).
 *   The least upper bound of two valid tokens A and B (i.e., sup(A,B)) is
 * easily obtained by eliminating the
 * constraints that are different in both tokens (or present in just one of
 * them). Also, if A (or B) is not valid then sup(A,B) = B (or A). If both are
 * invalid we get the empty set. From sup we can easily check if two tokens
 * are partially ordered:
 *            A <= B    <=>  sup(A,B) = B
 *
 * Note that <= is defined at a particular point in time (i.e.,tokens expire)
 * but    A<=B for all time t if  A<=B at t=t0 and B.expires >= A.expires
 *
 * In practice we use this in a couple of ways:
 *
 * 1) To check whether the token B can be used
 * to authenticate caOwner to a particular CA we create a  valid token A
 * representing the app info and caLocalName of the target CA  and check:
 *                   A<=B
 *
 * 2) Any client can request the 'Accounts' service to create a token A weaker
 * than B (as long as it knows B) provided:
 *             A<=B and A.expires <= B.expires.
 * and this simplifies delegating the management of tokens to a trusted third
 *  party.
 *
 *
 */


var validateToken = exports.validateToken = function(token) {
    if ((typeof token.algo === 'string') &&
        (!token.appPublisher ||
         (token.appPublisher && (typeof token.appPublisher === 'string'))) &&
        (!token.appLocalName ||
         (token.appLocalName && (typeof token.appLocalName === 'string'))) &&
        (!token.caLocalName ||
         (token.caLocalName && (typeof token.caLocalName === 'string'))) &&
        (token.caOwner && (typeof token.caOwner === 'string')) &&
        (!token.expires ||
         (token.expires && (typeof token.expires === 'number'))) &&
        (!token.signature ||
         (token.signature && (typeof token.signature === 'string')))) {
        var now = (new Date()).valueOf();
        return (!(token.expires)) || (token.expires >= now);
    } else {
        return false;
    }
};

var serializeToken = function(token) {
    var result = 'CAFTOKENv0.1|' + token.algo + '|';
    if (token.appPublisher) {
        result = result + token.appPublisher;
    }
    result = result + '|';
    if (token.appLocalName) {
        result = result + token.appLocalName;
    }
    result = result + '|' + token.caOwner + '|';
    if (token.caLocalName) {
        result = result + token.caLocalName;
    }
    return (result + '|' + (token.expires && token.expires.toString()));
};



var validateSignedToken = exports.validateSignedToken = function(pubKey,
                                                              signedToken) {
    if ((validateToken(signedToken)) &&
        (signedToken.algo) &&
        (signedToken.signature)) {
        Object.freeze(signedToken);
        if (signedToken.algo === 'RSA-SHA256') {
            var ver = crypto.createVerify('RSA-SHA256');
            ver.update(serializeToken(signedToken));
            return ver.verify(pubKey, signedToken.signature, 'base64');
        } else if (signedToken.algo === 'HMAC-SHA1') {
            var tokenKey = pubKey;
            var hash = crypto.createHmac('sha1', tokenKey)
                .update(serializeToken(signedToken))
                .digest('base64');
            return (hash === signedToken.signature);
        } else {
            return false;
        }
    } else {
        return false;
    }
};

exports.newToken = function(appPublisher, appLocalName, caOwner, caLocalName,
                            expires) {
    var token = {algo: '', appPublisher: appPublisher, appLocalName:
                 appLocalName, caOwner: caOwner, caLocalName: caLocalName,
                 expires: expires};
    if (validateToken(token)) {
        return token;
    } else {
        return null;
    }
};

exports.signToken = function(pubKey, privKey, algo, token) {
    token.algo = algo;
    if (validateToken(token)) {
        if (token.algo == 'RSA-SHA256') {
            var signer = crypto.createSign('RSA-SHA256');
            signer.update(serializeToken(token));
            token.signature = signer.sign(privKey, 'base64');
            return (validateSignedToken(pubKey, token) ? token : null);
        } else if (token.algo == 'HMAC-SHA1') {
            assert.ok(pubKey === privKey, 'need a symmetric key');
            var hash = crypto.createHmac('sha1', privKey)
                .update(serializeToken(token))
                .digest('base64');
            token.signature = hash;
            return (validateSignedToken(pubKey, token) ? token : null);
        } else {
            return null;
        }
    } else {
        return null;
    }
};

var TOKEN_PROPS = ['appPublisher', 'appLocalName', 'caLocalName'];

exports.lessOrEqual = function(tokenA, tokenB) {

    // assumed that they have been validated already

    if (tokenA.caOwner != tokenB.caOwner) {
        return false;
    }
    var sup = {};
    TOKEN_PROPS.forEach(function(prop) {
                            if (tokenA[prop] &&
                                (tokenA[prop] === tokenB[prop])) {
                                sup[prop] = tokenA[prop];
                            }
                        });
    var result = true;
    TOKEN_PROPS.forEach(function(prop) {
                            if (tokenB[prop] !== sup[prop]) {
                                result = false;
                            }
                        });
    return result;
};

var appNameToConstraints = exports.appNameToConstraints = function(appName,
                                                                   con) {
    con = con || {};
    var appLst = appName.split('-');
    if (appLst.length > 1) {
        con.appPublisher = appLst.shift();
        con.appLocalName = appLst.join('-');
    } else {
        con.appPublisher = 'root';
        con.appLocalName = appName;
    }
    return con;
};

var hostnameToConstraints = exports.hostnameToConstraints = function(hostname) {
    if (typeof hostname === 'string') {
        var con = {};
        var app = hostname && hostname.split('.')[0];
        if (app) {
            return appNameToConstraints(app, con);
        } else {
            return null;
        }
    } else {
        return null;
    }
};

/*
 *  url format:
 *   http(s)://<appPublisher>_<appLocalName>.whatever.com/app.html
 *
 *  where a missing <appPublisher> defaults to root
 */
exports.urlToConstraints = function(urlStr) {
    if (typeof urlStr === 'string') {
        var urlP = url.parse(urlStr);
        return hostnameToConstraints(urlP.hostname);
    } else {
        return null;
    }

};

exports.goToUrl = function(urlStr, caOwner, caLocalName, token) {
    if ((typeof urlStr === 'string') && (typeof caLocalName === 'string') &&
        (caOwner === token.caOwner)) {
        var urlP = url.parse(urlStr, true);
        urlP.query = urlP.query || {};
        urlP.query['caOwner'] = caOwner;
        urlP.query['caLocalName'] = caLocalName;
        urlP.query['token'] = JSON.stringify(token);
        delete urlP.search; // otherwise query ignored
        delete urlP.query['goTo'];
        delete urlP.query['unrestrictedToken'];
        return url.format(urlP);
    } else {
        return undefined;
    }
};

var validName = exports.validName = function(name) {
    return ((typeof name === 'string') &&
            (name.indexOf('#') === -1) &&
            (name.indexOf('_') === -1) &&
            (name.indexOf('$') === -1) &&
            (name.indexOf('|') === -1) &&
            (name !== 'root')); // root is reserved for built-in apps publisher
};

var HASH_ITERATIONS = exports.HASH_ITERATIONS = 10;
var HASH_ALGO = exports.HASH_ALGO = 'sha1';

exports.loadKey = function(fileName, dir, cb) {
    var keyFile = path.join(dir, fileName);
    fs.readFile(keyFile, 'utf8', cb);
};

exports.newPasswordHash = function(passwd) {
    return passwordHash.generate(passwd, {iterations: HASH_ITERATIONS,
                                          algorithm: HASH_ALGO});
};

exports.verifyPasswordHash = function(passwd, hash) {
    return passwordHash.verify(passwd, hash);
};


