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
 * Proxy to manage security policies from handler code.
 *
 * @name caf_security/proxy_security
 * @namespace
 * @augments gen_proxy
 *
 */
var caf = require('caf_core');
var genProxy = caf.gen_proxy;
var sec_util = require('./util_security');

/**
 * Factory method to create a proxy to manage security policies.
 *
 * @see sup_main
 */
exports.newInstance = function(context, spec, secrets, cb) {

    var that = genProxy.constructor(spec, secrets);
    var security = secrets.security_ca;

    /**
     * Gets the owner's name  of this CA.
     *
     * @return {string} The owner's name of this CA.
     *
     * @name caf_security/getOwner
     * @function
     */
    that.getOwner = function() {
        return security.getOwner();
    };

    /**
     * Gets the authenticated name of the caller of the current method.
     *
     * It is the owner's name in the `from` field of the message that
     * we are currently processing.
     *
     * @return {string} The name of the caller.
     *
     * @name caf_security/getCaller
     * @function
     *
     */
    that.getCaller = function() {
        return security.getCaller();
    };

    /**
     * Allows a principal to invoke certain method.
     *
     * @param {string} principal The caller that is authorized.
     * @param {string} method The method name or "*" for any method.
     *
     * @name caf_security/allow
     * @function
     *
     */
    that.allow = function(principal, method) {
        security.allow(principal, method);
    };

    /**
     * Blocks a principal from calling methods.
     *
     * The default policy is 'deny', so it has no effect unless method access
     * was previously allowed.
     *
     * @param {string} principal The caller to deny access.
     *
     * @name caf_security/deny
     * @function
     *
     */
    that.deny = function(principal) {
        security.deny(principal);
    };

    /**
     * Weakens an authentication token. It also handles an array of tokens.
     *
     * type of caf.tokenDesc is {appName:string=, caLocalName:string=}
     *
     * @param {caf.token} megaToken A token that we want to restrict.
     * @param {Array.<caf.tokenDesc> |<caf.tokenDesc> } tokenDesc A description
     *  of the new token.
     * @param {caf.cb} cb0 A callback to return the new token(s) or an error.
     *
     *
     * @name caf_security/attenuateToken
     * @function
      */
    that.attenuateToken = function(megaToken, tokenDesc, cb0) {
        var toCons = function(td) {
            var constraints = sec_util.appNameToConstraints(td.appName);
            constraints.caLocalName = td.caLocalName;
            constraints.caOwner = security.getOwner();
            return constraints;
        };
        if (Array.isArray(tokenDesc)) {
            var all = [];
            tokenDesc.forEach(function(x) { all.push(toCons(x));});
            security.attenuateToken(megaToken, all, cb0);
        } else {
            security.attenuateToken(megaToken, toCons(tokenDesc), cb0);
        }
    };

    Object.freeze(that);
    cb(null, that);
};
