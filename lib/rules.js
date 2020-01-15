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
const crypto = require('crypto');

/**
 * Basic authorization rules.
 *
 *
 * @module caf_security/rules
 */
const SIMPLE_RULE_TYPE = exports.SIMPLE_RULE_TYPE = 'caf.simpleRule';
const HASH_ALGO = 'md5';
const WILDCARD = '*';

/* The owner of this CA.*/
const SELF = exports.SELF = '!SELF';

/* The local name of this CA.*/
const CA_LOCAL = exports.CA_LOCAL = '!CA_LOCAL';


const checkSimpleRule = function(rule) {
    if (rule.type !== SIMPLE_RULE_TYPE) {
        const err = new Error('Invalid rule');
        err['rule'] = rule;
        throw err;
    }
};

/**
 * Computes a content-based identifier for a simple rule.
 *
 *
 * @param {ruleType} rule A simple rule.
 * @return {string} A unique identifier based on the contents of that rule.
 * @throws {Error} Invalid rule.
 *
 * @memberof! module:caf_security/rules
 * @alias computeRuleId
 *
 */
exports.computeRuleId = function(rule) {
    checkSimpleRule(rule);

    const tokenId = function(t) {
        t = t || {};
        return [
            t.appPublisher || null, t.appLocalName || null,
            t.caOwner || null, t.caLocalName || null, t.expiresAfter || null
        ];
    };

    const p = [
        SIMPLE_RULE_TYPE, tokenId(/** @type simpleRuleType*/ (rule).ac),
        rule.methods || null
    ];
    const pStr = JSON.stringify(p);
    return crypto.createHash(HASH_ALGO).update(pStr).digest('hex');
};

/**
 * Preprocess an array of rules for quick authorization checks using a trie
 *  based data structure.
 *
 * @param {string} meOwner The owner of the target CA.
 * @param {string} meLocalName The local name of the target CA.
 * @param {Array.<ruleType>} rules A set of rules to pre-process.
 *
 * @return {ruleEngineType} A trie based data structure to speed up checks.
 *
 * @memberof! module:caf_security/rules
 * @alias newRuleEngine
 */
exports.newRuleEngine = function(meOwner, meLocalName, rules) {
    /** @type ruleEngineType*/
    const rE = {};
    const addOneRule = function(rule) {

        checkSimpleRule(rule);
        const caOwner = rule.ac.caOwner === SELF ? meOwner : rule.ac.caOwner;
        const caLocalName = rule.ac.caLocalName === CA_LOCAL ?
            meLocalName :
            rule.ac.caLocalName;
        const p = [
            caOwner || WILDCARD,
            caLocalName || WILDCARD,
            rule.methods || WILDCARD
        ];
        const insertRule = function(ruleE, pList) {
            if (pList.length > 1) {
                const head = pList.shift();
                if (!ruleE[head]) {
                    ruleE[head] = {};
                }
                insertRule(ruleE[head], pList);
            } else {
                // expand methods
                const m = pList.shift();
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

    const optimize = function(rules) {
        if (typeof rules === 'boolean') {
            return rules;
        } else {
            const result = {};
            const collapse = Object.keys(rules)
                .some(function(x) {
                    const value = optimize(rules[x]);
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
 * @param {ruleEngineType} rE A trie based data structure to speed up checks.
 *
 * @return {boolean} True if authorized.
 *
 * @memberof! module:caf_security/rules
 * @alias isAuthorized
 */
exports.isAuthorized = function(caOwner, caLocalName, method, rE) {
    if (rE === null) {
        return true;
    }

    // breadth-first, worse case ten look-ups
    // level 1
    const pOwner = rE[caOwner];
    if (pOwner === null) {
        return true;
    }

    const pWildcard = rE[WILDCARD];
    /*  should be removed by 'optimize'
    if (pWildcard === null) {
        return true;
    }
     */

    // level 2
    const pOwnerWildcard = pOwner && pOwner[WILDCARD];
    /* should be removed by 'optimize'
    if (pOwnerWildcard === null) {
        return true;
    }
     */

    const pOwnerLocal = pOwner && pOwner[caLocalName];
    if (pOwnerLocal === null) {
        return true;
    }

    const pWildcardWildcard = pWildcard && pWildcard[WILDCARD];
    /* should be removed by 'optimize'
    if (pWildcardWildcard === null) {
        return true;
    }
     */

    const pWildcardLocal = pWildcard && pWildcard[caLocalName];
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
 *  @see {@link module:caf_security/proxy_security#addRule}.
 *
 *  @param {(Array.<string>|string)=} methods Methods to enable.
 *  @param {string=} caOwner Owner of the calling CA.
 *  @param {string=} caLocalName Local name of the calling CA/
 *
 *  @return {ruleType} An authorization  rule.
 *
 * @memberof! module:caf_security/rules
 * @alias newSimpleRule
 */
exports.newSimpleRule = function(methods, caOwner, caLocalName) {
    /** @type simpleRuleType*/
    const result = {type: SIMPLE_RULE_TYPE};
    if (methods) {
        result.methods = methods;
    }
    /** @type CANameType*/
    const ac = {};
    if (caOwner) {
        ac.caOwner = caOwner;
    }
    if (caLocalName) {
        ac.caLocalName = caLocalName;
    }
    result.ac = ac;
    return result;
};
