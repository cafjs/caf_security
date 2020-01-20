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
 * Proxy to manage security policies from application code.
 *
 * @module caf_security/proxy_security
 * @augments external:caf_components/gen_proxy
 */
// @ts-ignore: augments not attached to a class
const caf_comp = require('caf_components');
const genProxy = caf_comp.gen_proxy;
const rules = require('./rules');
const aggregates = require('./aggregates');

exports.newInstance = async function($, spec) {

    const that = genProxy.create($, spec);

    /**
     * Gets the application name.
     *
     * @return {string} The application name.
     *
     * @memberof! module:caf_security/proxy_security#
     * @alias getAppName
     */
    that.getAppName = function() {
        return $._.getAppName();
    };

    /**
     * Gets the authenticated caller's name.
     *
     * It matches the `from` field of the message that we are currently
     * processing, i.e., `<caOwner>-<caLocalName>`.
     *
     * @return {string} The name of the caller.
     *
     * @memberof! module:caf_security/proxy_security#
     * @alias getCallerFrom
     */
    that.getCallerFrom = function() {
        return $._.getCallerFrom();
    };


    /**
     * Constructor for a simple rule, i.e., of type `"caf.simpleRule"`.
     *
     * @see {@link module:caf_security/proxy_security#addRule}.
     *
     *  @param {(Array.<string>|string)=} methods Methods to enable. Defaults
     * to all.
     *  @param {string=} caOwner Owner of the calling CA.
     *  @param {string=} caLocalName Local name of the calling CA/
     *
     *  @return {ruleType} An authorization  rule.
     *
     * @memberof! module:caf_security/proxy_security#
     * @alias newSimpleRule
     */
    that.newSimpleRule = function(methods, caOwner, caLocalName) {
        return rules.newSimpleRule(methods, caOwner, caLocalName);
    };

    /**
     * Constructor for a rule that uses an `AggregateMap` to represent a linked
     * local namespace.
     *
     * Note that aggregate rules are only active if the corresponding
     * `AggregateMap` has been added using the `caf_sharing` plugin.
     *
     * @see {@link module:caf_security/proxy_security#addRule}.
     *
     *  @param {(Array.<string>|string)=} methods Methods to enable. Defaults
     * to all.
     *  @param {string} aggregateMapAlias The alias that we used to
     * instantiate the AggregateMap.
     *
     *  @return {ruleType} An authorization  rule.
     *
     * @memberof! module:caf_security/proxy_security#
     * @alias newAggregateRule
     */
    that.newAggregateRule = function(methods, aggregateMapAlias) {
        return aggregates.newAggregateRule(methods, aggregateMapAlias);
    };

    /**
     * A symbol representing the owner of this CA, i.e., `"!SELF"`.
     *
     * @type string
     * @memberof! module:caf_security/proxy_security#
     * @alias SELF
     */
    that.SELF = rules.SELF;

    /**
     * A symbol representing the local name of this CA, i.e., `"!CA_LOCAL"`.
     *
     * @type string
     * @memberof! module:caf_security/proxy_security#
     * @alias CA_LOCAL
     */
    that.CA_LOCAL = rules.CA_LOCAL;

    /**
     * Checks whether a caller is authorized to invoke certain method.
     *
     * This explicit check is typically not needed because the framework
     * enforces access policy, but it can be useful for debugging or to validate
     * application-level checks.
     *
     * @param {string} caller A CA name of the form  `<caOwner>-<caLocalName>`.
     * @param {string} method A method name.
     *
     * @return {boolean} True if access would be granted, false otherwise.
     *
     * @memberof! module:caf_security/proxy_security#
     * @alias isAuthorized
     *
     */
    that.isAuthorized = function(caller, method) {
        return $._.isAuthorized(caller, method, true);
    };

    /**
     * Adds a rule that allows a principal to invoke certain methods.
     *
     * The type can be `simpleRuleType` or  `aggregateRuleType`
     *
     * The type of `ruleType` when the rule type is `simpleRuleType`:
     *
     *     { type: 'caf.simpleRule', ac: {caOwner: string=,
     *                                    caLocalName: string=},
     *       methods: (Array.<string> | string)=}
     *
     * a missing field means a wildcard, `"!SELF"` represents the owner of
     * this CA, and `"!CA_LOCAL"` matches the local name of this CA.
     *
     *  For example:
     *
     *      {type: 'caf.simpleRule', ac: {caOwner: "!SELF",
     *                                    caLocalName: "!CA_LOCAL"}}
     *
     *  gives the owner, within an authenticated session, full access to this
     * CA. This is a sensible default.
     *
     *      {type: 'caf.simpleRule', ac: {caOwner: '!SELF'}}
     *
     * gives any CA with the same owner full access to this CA.
     *
     *      {type: 'caf.simpleRule', ac: {caOwner: '!SELF', caLocalName: 'bar'},
     *       methods: 'foo'}
     *
     * grants permission to CA `bar`, of the same owner, to  invoke method
     * `foo`.
     *
     * The type  of `ruleType` when the rule type is `aggregateRuleType`:
     *
     *      {type: 'caf.aggregateRule', alias : string,
     *       methods: (Array.<string> | string)=}
     *
     *  where `alias` is the `AggregateMap` alias in the `sharing` plugin
     * context. See {@link external:caf_sharing}.
     *
     * For example, if `alias` is `foo`, the map is `this.$.sharing.$.foo`.
     *
     * @param {ruleType} newRule A new authorization rule.
     *
     * @return {string} A rule identifier.
     *
     * @memberof! module:caf_security/proxy_security#
     * @alias addRule
     *
     */
    that.addRule = function(newRule) {
        return $._.addRule(newRule);
    };

    /**
     * Lists current active rules.
     *
     * It returns a deep frozen copy of the current rules.
     *
     * @return {Object.<string, ruleType>} A map using rule ids as keys and
     *  rule contents as values.
     *
     * @memberof! module:caf_security/proxy_security#
     * @alias listRules
     *
     */
    that.listRules = function() {
        return $._.listRules();
    };

    /**
     * Computes a content-based identifier for a rule.
     *
     * @param {ruleType} rule A rule.
     *
     * @return {string} A unique identifier based on the contents of that rule.
     *
     * @throws {Error} Invalid rule.
     *
     * @memberof! module:caf_security/proxy_security#
     * @alias computeRuleId
     *
     */
    that.computeRuleId = function(rule) {
        return $._.computeRuleId(rule);

    };

    /**
     * Removes a rule.
     *
     * @param {string} ruleId The identifier of the rule to be removed.
     *
     * @memberof! module:caf_security/proxy_security#
     * @alias removeRule
     *
     */
    that.removeRule = function(ruleId) {
        $._.removeRule(ruleId);
    };


    /**
     * Checks that a serialized token is trusted by this app.
     *
     * The type of `tokenType` is
     *
     *       {appPublisher: string=, appLocalName:string=, caOwner: string=,
     *        caLocalName: string=, expiresAfter: string=}
     *
     * @param {string} tokenStr A serialized token to validate.
     *
     * @return {tokenType|null} A parsed and validated token, or `null` if token
     *  invalid.
     *
     * @memberof! module:caf_security/proxy_security#
     * @alias verifyToken
     *
     */
    that.verifyToken = function(tokenStr) {
        return $._.verifyToken(tokenStr);
    };

    /**
     * Weakens an authentication token generating one (or many) token(s).
     *
     * type of `tokenDescriptionType` is
     *
     *      {appPublisher: (string|null)=, appLocalName: (string|null)=,
     *       caOwner: (string|null)=, caLocalName: (string|null)=,
     *       durationInSec: number=}
     *
     * A `null` value in the token description means force the current value.
     *
     * An `undefined` value means remove the constraint.
     *
     * @param {tokenType} megaToken A token that we want to restrict.
     * @param {Array.<tokenDescriptionType> |tokenDescriptionType } tokenDesc A
     * description  of the new token(s).
     * @param {cbType} cb0 A callback to return the new token(s) or an error.
     *
     *
     * @memberof! module:caf_security/proxy_security#
     * @alias attenuateToken
      */
    that.attenuateToken = function(megaToken, tokenDesc, cb0) {
        $._.attenuateToken(megaToken, tokenDesc, cb0);
    };

    Object.freeze(that);
    return [null, that];
};
