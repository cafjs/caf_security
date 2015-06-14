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
var caf_comp = require('caf_components');
var genProxy = caf_comp.gen_proxy;
var tokens = require('./tokens');
var rules = require('./rules');
var aggregates = require('./aggregates');

/**
 * Factory method to create a proxy to manage security policies.
 *
 * @see sup_main
 */
exports.newInstance = function($, spec, cb) {

    var that = genProxy.constructor($, spec);


    /**
     * Gets the application name.
     *
     * @return {string} The application name.
     * @name  caf_security/__ca_getAppName__
     * @function
     */
    that.getAppName = function() {
        return $._.getAppName();
    };

    /**
     * Gets the authenticated name of the caller of the current method.
     *
     * It is the `from` field of the message that we are currently processing,
     * i.e.,  `<caOwner>-<caLocalName>`.
     *
     * @return {string} The name of the caller.
     *
     * @name caf_security/getCaller
     * @function
     *
     */
    that.getCallerFrom = function() {
        return $._.getCallerFrom();
    };


    /**
     * Constructor for a simple rule.
     *
     * The type 'caf.rule' is  {type: 'caf.simpleRule', ac : caf.token,
     *                          methods: Array.<string> | string}
     *
     * The type of caf.token is {appPublisher: string=, appLocalName:string=,
     *              caOwner: string=, caLocalName: string=,
     *              expiresAfter: string= }
     * but we assume intra-app use and no expiration (i.e., only the `caOwner`
     *  and `caLocalName` fields are relevant).
     *
     *  @param {Array.<string>= | string=} methods Methods to enable.
     *  @param {string=} caOwner Owner of the calling CA.
     *  @param {string=} caLocalName Local name of the calling CA/
     *
     *  @return {caf.rule} An authorization  rule.
     */
    that.newSimpleRule = function(methods, caOwner, caLocalName) {
        return rules.newSimpleRule(methods, caOwner, caLocalName);
    };

    /**
     * Constructor for a rule that uses an AggregateMap to represent a linked
     * local namespace (SDSI).
     *
     * Note that aggregate rules are only active if the corresponding
     * AggregateMap has been added using the `caf_sharing` plugin.
     *
     * The type 'caf.rule' is  {type: 'caf.aggregateRule', alias : string,
     *                          methods: Array.<string> | string}
     *
     *  @param {Array.<string>= | string=} methods Methods to enable.
     *  @param {string} aggregateMapAlias The alias that we used to
     * instantiate the AggregateMap (see caf_sharing#proxy_sharing)
     *
     *  @return {caf.rule} An authorization  rule.
     *
     */
    that.newAggregateRule = function(methods, aggregateMapAlias) {
        return aggregates.newAggregateRule(methods, aggregateMapAlias);
    };

    /** The owner of this CA.*/
    that.SELF = rules.SELF;

    /** The local name of this CA.*/
    that.CA_LOCAL = rules.CA_LOCAL;

    /**
     * Adds a rule to allow a  principal to invoke certain methods.
     *
     * The type 'caf.rule' is  {type: 'caf.simpleRule', caOwner: string=,
     *                          caLocalName:string=,
     *                          methods: Array.<string> | string}
     *
     * where a missing field means a wildcard, the string '!SELF' represents
     * the owner of this CA, the string '!CA_LOCAL' is the local name of this
     * CA.
     *
     *  For example:
     *
     *    {type: 'caf.simpleRule', caOwner:'!SELF', caLocalName:'!CA_LOCAL'}
     * gives an owner with an authenticated session full access to this CA.
     *  This is a sensible default.
     *
     *    {type: 'caf.simpleRule', caOwner:'!SELF'}, gives also full access to
     *  any  CA  sharing owner with this CA.
     *
     *    {type: 'caf.simpleRule', caOwner:'!SELF', caLocalName:'bar',
     *     methods: 'foo'}, enables access to the method with name 'foo' for
     *  the CA 'bar', of the same owner.
     *
     *
     * @param {caf.rule} newRule A new authorization rule.
     *
     * @return {string} A rule identifier.
     *
     * @name caf_security/allow
     * @function
     *
     */
    that.addRule = function(newRule) {
        return $._.addRule(newRule);
    };

    /**
     * Lists current rules.
     *
     * It returns a frozen, deep copy of the current rules.
     *
     * @return {Object.<string, caf.rule>} A map using rule ids as keys and
     *  rule contents as values.
     *
     * @name caf_security/listRules
     * @function
     *
     */
    that.listRules = function() {
        return $._.listRules();
    };

    /**
     * Computes a content-based identifier for a rule.
     *
     * @param {caf.rule} rule A rule.
     *
     * @return {string} A unique identifier based on the contents of that rule.
     *
     * @throws {Error} Invalid rule.
     *
     * @name caf_security/computeRuleId
     * @function
     *
     */
    that.computeRuleId = function(rule) {
        return $._.computeRuleId(rule);

    };

    /**
     * Removes a rule.
     *
     * @param {string} ruleId The identifier of the rule to be removed
     *
     * @name caf_security/removeRule
     * @function
     *
     */
    that.removeRule = function(ruleId) {
        $._.removeRule(ruleId);
    };

    /**
     * Weakens an authentication token. It also handles an array of tokens.
     *
     * type of caf.tokenDesc is {appPublisher: string= | null=,
     *       appLocalName:string= | null=,
     *       caOwner: string= | null=, caLocalName:string= | null=,
     *       durationInSec:number=}
     *
     * where a 'null' value means use the value of the current app name or
     * owner or ... and an 'undefined' value means no constraint.
     *
     * @param {caf.token} megaToken A token that we want to restrict.
     * @param {Array.<caf.tokenDesc> |caf.tokenDesc } tokenDesc A description
     *  of the new token.
     * @param {caf.cb} cb0 A callback to return the new token(s) or an error.
     *
     *
     * @name caf_security/attenuateToken
     * @function
      */
    that.attenuateToken = function(megaToken, tokenDesc, cb0) {
        $._.attenuateToken(megaToken, tokenDesc, cb0);
    };

    Object.freeze(that);
    cb(null, that);
};
