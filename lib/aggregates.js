// Modifications copyright 2020 Caf.js Labs and contributors
/*!
Copyright 2014 Hewlett-Packard Development Company, L.P.

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
 * Authorization rule that implements linked local namespaces with
 *  an `AggregateMap` (see {@link external:caf_sharing/AggregateMap}).
 *
 * @module caf_security/aggregates
 */
const crypto = require('crypto');
const json_rpc = require('caf_transport').json_rpc;

const AGGREGATE_RULE_TYPE = exports.AGGREGATE_RULE_TYPE = 'caf.aggregateRule';
const HASH_ALGO = 'md5';

const checkAggregateRule = function(rule) {
    if (rule.type !== AGGREGATE_RULE_TYPE) {
        const err = new Error('Invalid aggregate rule');
        err['rule'] = rule;
        throw err;
    }
};

/**
 * Computes a content-based identifier for a rule.
 *
 * @see {@link module:caf_security/proxy_security#addRule}.
 *
 * @param {ruleType} rule A rule.
 * @return {string} A unique identifier based on the contents of that rule.
 * @throws {Error} Invalid rule.
 *
 * @memberof! module:caf_security/aggregates
 * @alias computeRuleId
 *
 */
exports.computeRuleId = function(rule) {
    checkAggregateRule(rule);

    const p = [
        AGGREGATE_RULE_TYPE, /** @type aggregateRuleType*/ (rule).alias,
        rule.methods || null
    ];
    const pStr = JSON.stringify(p);
    return crypto.createHash(HASH_ALGO).update(pStr).digest('hex');
};

/**
 * Preprocess an array of rules for quick authorization checks.
 *
 * @param {Object} ca The CA that contains the security plugin.
 * @param {Array.<ruleType>} rules A set of rules to pre-process.
 *
 * @return {ruleEngineType} An engine to speed up checks.
 *
 * @memberof! module:caf_security/aggregates
 * @alias newRuleEngine
 */
exports.newRuleEngine = function(ca, rules) {
    /** @type ruleEngineType*/
    const rE = {};
    // inverse lookup table
    const mToMap = {};

    rules = rules || [];

    rules.forEach(function(rule) {
        checkAggregateRule(rule);
        let method = (rule.methods ? rule.methods : '*');
        method = (Array.isArray(method) ? method : [method]);
        method.forEach(function(m) {
            let value = mToMap[m];
            value = (value ? value : []);
            value.push(/** @type aggregateRuleType*/ (rule).alias);
            mToMap[m] = value;
        });
    });

    const isAuthorizedOne = function($$, aggArray, name) {
        if (Array.isArray(aggArray)) {
            return aggArray.some(function(x) {
                const agg = $$[x];
                if (agg) {
                    return (agg.getAll(name).length > 0);
                } else {
                    return false;
                }
            });
        } else {
            return false;
        }
    };

    rE.isAuthorized = function(caOwner, caLocalName, method) {
        if (ca.$.sharing) {
            const fullName = json_rpc.joinName(caOwner, caLocalName);
            const $$ = ca.$.sharing.$.proxy.$;
            const wild = mToMap['*'];
            if (wild) {
                if (isAuthorizedOne($$, wild, caOwner)) {
                    return true;
                }
                if (isAuthorizedOne($$, wild, fullName)) {
                    return true;
                }
            }
            const m = mToMap[method];
            if (m) {
                if (isAuthorizedOne($$, m, caOwner)) {
                    return true;
                }
                if (isAuthorizedOne($$, m, fullName)) {
                    return true;
                }
            }
        }
        return false;
    };

    return rE;
};

/**
 * Checks whether a CA is authorized to make a method call.
 *
 * @param {string} caOwner The owner of the calling CA.
 * @param {string} caLocalName The local name of the calling CA.
 * @param {string} method A method to authorize.
 * @param {ruleEngineType} rE A data structure to speed up checks.
 *
 * @return {boolean} True if authorized.
 *
 * @memberof! module:caf_security/aggregates
 * @alias isAuthorized
 */
exports.isAuthorized = function(caOwner, caLocalName, method, rE) {
    return rE.isAuthorized(caOwner, caLocalName, method);
};


/**
 * Constructor for a rule that uses an `AggregateMap` to represent a linked
 * local namespace.
 *
 * Note that aggregate rules are only active if the corresponding
 * `AggregateMap` has been added using the `caf_sharing` plugin.
 *
 *  @see {@link external:caf_sharing}
 *  @see {@link module:caf_security/proxy_security#addRule}.
 *
 *  @param {Array.<string>|string|null} methods Methods to enable.
 *  @param {string} aggregateMapAlias The alias that we used to
 * instantiate the `AggregateMap`.
 *
 *  @return {ruleType} An authorization rule.
 *
 * @memberof! module:caf_security/aggregates
 * @alias newAggregateRule
 */
exports.newAggregateRule = function(methods, aggregateMapAlias) {
    /** @type aggregateRuleType*/
    const result = {type: AGGREGATE_RULE_TYPE, alias: aggregateMapAlias};
    if (methods) {
        result.methods = methods;
    }
    return result;
};
