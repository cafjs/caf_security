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

"use strict";
/**
 * Authorization rule that uses linked local namespaces (SDSI) implemented with
 *  an AggregateMap (see `caf_sharing` plugin).
 *
 * @name caf_security/aggregates
 * @namespace
 */
var crypto = require('crypto');
var json_rpc = require('caf_transport').json_rpc;

var AGGREGATE_RULE_TYPE = exports.AGGREGATE_RULE_TYPE = 'caf.aggregateRule';
var HASH_ALGO = 'md5';

var checkAggregateRule = function(rule) {
    if (rule.type !== AGGREGATE_RULE_TYPE) {
        var err = new Error('Invalid aggregate rule');
        err.rule = rule;
        throw err;
    }
};

/**
 * Computes a content-based identifier for a rule.
 *
 * The type 'caf.rule' is  {type: 'caf.aggregateRule', alias : string,
 *                          methods: Array.<string> | string}
 *
 * @param {caf.rule} rule A rule.
 *
 * @return {string} A unique identifier based on the contents of that rule.
 *
 * @throws {Error} Invalid rule.
 *
 * @name aggregates/computeRuleId
 * @function
 *
 */
var computeRuleId = exports.computeRuleId = function(rule) {
    checkAggregateRule(rule);

    var p = [AGGREGATE_RULE_TYPE, rule.alias, rule.methods || null];
    var pStr = JSON.stringify(p);
    return crypto.createHash(HASH_ALGO).update(pStr).digest('hex');
};

/**
 * Preprocess an array of rules for quick authorization checks.
 *
 * @param {Object} ca The CA that contains the security plugin.
 * @param {Array.<caf.rule>} rules A set of rules to pre-process.
 *
 * @return {Object} An engine to speed up checks.
 *
 * @name aggregates/newRuleEngine
 * @function
 */
var newRuleEngine = exports.newRuleEngine = function(ca, rules) {
    var rE = {};
    // inverse lookup table
    var mToMap = {};

    rules = rules || [];

    rules.forEach(function(rule) {
        checkAggregateRule(rule);
        var method = (rule.methods ? rule.methods : '*');
        method = (Array.isArray(method) ? method : [method]);
        method.forEach(function(m) {
            var value = mToMap[m];
            value = (value ? value : []);
            value.push(rule.alias);
            mToMap[m] = value;
        });
    });

    var isAuthorizedOne = function($$, aggArray, name) {
        if (Array.isArray(aggArray)) {
            return aggArray.some(function(x) {
                var agg = $$[x];
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
            var fullName = json_rpc.joinName(caOwner, caLocalName);
            var $$ = ca.$.sharing.$.proxy.$;
            var wild = mToMap['*'];
            if (wild) {
                if (isAuthorizedOne($$, wild, caOwner)) {
                    return true;
                }
                if (isAuthorizedOne($$, wild, fullName)) {
                    return true;
                }
            }
            var m = mToMap[method];
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
 * @param {Object} rE A data structure to speed up checks.
 *
 * @return {boolean} True if authorized.
 *
 * @name aggregates/isAuthorized
 * @function
 */
var isAuthorized = exports.isAuthorized = function(caOwner, caLocalName, method,
                                                   rE) {
    return rE.isAuthorized(caOwner, caLocalName, method);
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
 * @name aggregates/newAggregateRule
 * @function
 */
var newAggregateRule = exports.newAggregateRule = function(methods,
                                                           aggregateMapAlias) {
    var result =  {type: AGGREGATE_RULE_TYPE};
    if (methods) {
        result.methods = methods;
    }
    result.alias = aggregateMapAlias;
    return result;
};
