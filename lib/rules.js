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
var crypto = require('crypto');

/**
 * Authorization rules.
 *
 *
 * @name caf_security/rules
 * @namespace
 */

var SIMPLE_RULE_TYPE = exports.SIMPLE_RULE_TYPE = 'caf.simpleRule';
var HASH_ALGO = 'md5';
var WILDCARD = '*';

/** The owner of this CA.*/
var SELF = exports.SELF = '!SELF';

/** The local name of this CA.*/
var CA_LOCAL = exports.CA_LOCAL = '!CA_LOCAL';


var checkSimpleRule = function(rule) {
    if (rule.type !== SIMPLE_RULE_TYPE) {
        var err = new Error('Invalid rule');
        err.rule = rule;
        throw err;
    }
};

/**
 * Computes a content-based identifier for a rule.
 *
 * The type 'caf.rule' is  {type: 'caf.simpleRule', ac : caf.token,
 *                          methods: Array.<string> | string}
 *
 * The type of caf.token is {appPublisher: string=, appLocalName:string=,
 *                           caOwner: string=, caLocalName: string=,
 *                           expiresAfter: string= }
 *
 * but we assume intra-app use only and no expiration (i.e., only the `caOwner`
 *  and `caLocalName` fields are relevant).
 *
 * @param {caf.rule} rule A rule.
 *
 * @return {string} A unique identifier based on the contents of that rule.
 *
 * @throws {Error} Invalid rule.
 *
 * @name rules/computeRuleId
 * @function
 *
 */
exports.computeRuleId = function(rule) {
    checkSimpleRule(rule);

    var tokenId = function(t) {
        t = t || {};
        return [t.appPublisher || null, t.appLocalName || null,
                t.caOwner || null, t.caLocalName || null,
                t.expiresAfter || null];
    };

    var p = [SIMPLE_RULE_TYPE, tokenId(rule.ac), rule.methods || null];
    var pStr = JSON.stringify(p);
    return crypto.createHash(HASH_ALGO).update(pStr).digest('hex');
};

/**
 * Preprocess an array of rules for quick authorization checks using a trie
 *  based data structure.
 *
 * @param {string} meOwner The owner of the target CA.
 * @param {string} meLocalName The local name of the target CA.
 * @param {Array.<caf.rule>} rules A set of rules to pre-process.
 *
 * @return {Object} A trie based data structure to speed up checks.
 *
 * @name rules/newRuleEngine
 * @function
 */
exports.newRuleEngine = function(meOwner, meLocalName, rules) {
    var rE = {};
    var addOneRule = function(rule) {

        checkSimpleRule(rule);
        var p = [(rule.ac.caOwner === SELF ? meOwner :
                  rule.ac.caOwner) || WILDCARD,
                 (rule.ac.caLocalName === CA_LOCAL ? meLocalName :
                  rule.ac.caLocalName) || WILDCARD,
                 rule.methods || WILDCARD];
        var insertRule = function(ruleE, pList) {
            if (pList.length > 1) {
                var head = pList.shift();
                if (!ruleE[head]) {
                    ruleE[head] = {};
                }
                insertRule(ruleE[head], pList);
            } else {
                // expand methods
                var m = pList.shift();
                if (Array.isArray(m)) {
                    m.forEach(function(x) { ruleE[x] = true;});
                } else {
                    ruleE[m] = true;
                }
            }
        };
        insertRule(rE, p);
    };

    rules.forEach(function(rule) { addOneRule(rule);});

    var optimize = function(rules) {
        if (typeof rules === 'boolean') {
            return rules;
        } else {
            var result = {};
            var collapse = Object.keys(rules)
                .some(function(x) {
                    var value = optimize(rules[x]);
                    if ((x === WILDCARD) &&
                                 ((value === null) ||
                                  (value && (typeof value === 'boolean')))) {
                        return true; // all authorized
                    } else {
                        result[x] = value;
                        return false;
                    }
                });
            // 'null' means authorized
            return (collapse ? null : result);
        }
    };

    return optimize(rE);
};

/**
 * Checks whether a CA is authorized to make a method call.
 *
 * @param {string} caOwner The owner of the calling CA.
 * @param {string} caLocalName The local name of the calling CA.
 * @param {string} method A method to authorize.
 * @param {Object} rE A trie based data structure to speed up checks.
 *
 * @return {boolean} True if authorized.
 *
 * @name rules/isAuthorized
 * @function
 */
exports.isAuthorized = function(caOwner, caLocalName, method, rE) {
    if (rE === null) {
        return true;
    }

    // breadth-first, worse case ten look-ups
    // level 1
    var pOwner = rE[caOwner];
    if (pOwner === null) {
        return true;
    }

    var pWildcard = rE[WILDCARD];
    /*  should be removed by 'optimize'
    if (pWildcard === null) {
        return true;
    }
     */

    // level 2
    var pOwnerWildcard = pOwner && pOwner[WILDCARD];
    /* should be removed by 'optimize'
    if (pOwnerWildcard === null) {
        return true;
    }
     */

    var pOwnerLocal = pOwner && pOwner[caLocalName];
    if (pOwnerLocal === null) {
        return true;
    }

    var pWildcardWildcard = pWildcard && pWildcard[WILDCARD];
    /* should be removed by 'optimize'
    if (pWildcardWildcard === null) {
        return true;
    }
     */

    var pWildcardLocal = pWildcard && pWildcard[caLocalName];
    if (pWildcardLocal === null) {
        return true;
    }

    // level 3
    if (pOwnerWildcard && pOwnerWildcard[method]) {
        return true;
    }

    if (pOwnerLocal && pOwnerLocal[method]) {
        return true;
    }

    if (pWildcardWildcard && pWildcardWildcard[method]) {
        return true;
    }

    if (pWildcardLocal && pWildcardLocal[method]) {
        return true;
    }

    return false;
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
 *
 * @name rules/newSimpleRule
 * @function
 */
exports.newSimpleRule = function(methods, caOwner, caLocalName) {
    var result = {type: SIMPLE_RULE_TYPE};
    if (methods) {
        result.methods = methods;
    }
    result.ac = {};
    if (caOwner) {
        result.ac.caOwner = caOwner;
    }
    if (caLocalName) {
        result.ac.caLocalName = caLocalName;
    }
    return result;
};
