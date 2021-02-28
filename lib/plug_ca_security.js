// Modifications copyright 2020 Caf.js Labs and contributors
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
 * Security plug that authorizes method invocations for this CA.
 *
 * Decisions are based on the authenticated request field `from`
 * and an internal policy.
 *
 * Properties:
 *
 *      {defaultRules: Array.<ruleType>}
 *
 * `defaultsRules` is a list of rules applied to all CAs. For rule formats see
 * {@link module:caf_security/proxy_security#addRule}
 *
 * @module caf_security/plug_ca_security
 * @augments external:caf_components/gen_plug_ca
 *
 */
// @ts-ignore: augments not attached to a class
const assert = /** @type {typeof import('assert')} */(require('assert'));
const caf_comp = require('caf_components');
const myUtils = caf_comp.myUtils;
const genPlugCA = caf_comp.gen_plug_ca;
const json_rpc = require('caf_transport').json_rpc;
const rules = require('./rules');
const aggregates = require('./aggregates');

exports.newInstance = async function($, spec) {
    try {
        /* Compiled rules engine. */
        var rE = null;
        /* Ditto for aggregates engine*/
        var rEAggregates = null;

        var caller = null;

        const that = genPlugCA.create($, spec);

        /*
         * The contents of this variable are always checkpointed before
         * any state externalization (see `gen_transactional`).
         *
         * `acl` key is Object.<id: string, ruleType>
         */
        that.state = {acl: {}};

        assert.ok(Array.isArray(spec.env.defaultRules),
                  "'spec.env.defaultRules' is not an array.");

        that.computeRuleId = function(rule) {
            if (rule.type === rules.SIMPLE_RULE_TYPE) {
                return rules.computeRuleId(rule);
            } else if (rule.type === aggregates.AGGREGATE_RULE_TYPE) {
                return aggregates.computeRuleId(rule);
            } else {
                const err = new Error('Invalid rule type');
                err['rule'] = rule;
                throw err;
            }
        };

        spec.env.defaultRules.forEach(function(x) {
            that.state.acl[that.computeRuleId(x)] = x;
        });
        const caNameSplit = json_rpc.splitName($.ca.__ca_getName__());

        const updateRules = function() {
            const values = [];
            const ids = Object.keys(that.state.acl);
            ids.forEach(x => values.push(that.state.acl[x]));
            const valuesSimple = values.filter(function(x) {
                return (x.type === rules.SIMPLE_RULE_TYPE);
            });
            rE = rules.newRuleEngine(caNameSplit[0], caNameSplit[1],
                                     valuesSimple);
            const valuesAgg = values.filter(function(x) {
                return (x.type === aggregates.AGGREGATE_RULE_TYPE);
            });
            rEAggregates = aggregates.newRuleEngine($.ca, valuesAgg);
        };

        updateRules();

        // transactional ops
        const target = {
            addRuleImpl: function(newRule, cb0) {
                that.state.acl[that.computeRuleId(newRule)] = newRule;
                updateRules();
                cb0(null);
            },
            removeRuleImpl: function(ruleId, cb0) {
                delete that.state.acl[ruleId];
                updateRules();
                cb0(null);
            }
        };

        that.__ca_setLogActionsTarget__(target);

        that.addRule = function(newRule) {
            that.__ca_lazyApply__('addRuleImpl', [newRule]);
            return that.computeRuleId(newRule);
        };

        that.removeRule = function(ruleId) {
            that.__ca_lazyApply__('removeRuleImpl', [ruleId]);
        };

        that.listRules = function() {
            const result = myUtils.deepClone(that.state.acl);
            Object.freeze(result);
            return result;
        };

        that.getCallerFrom = function() {
            return caller;
        };

        that.getAppName = function() {
            return $._.$.security.__ca_getAppName__();
        };

        that.attenuateToken = function(megaToken, constraints, cb0) {
            return $._.$.security.__ca_attenuateToken__(megaToken, constraints,
                                                        cb0);
        };

        that.verifyToken = function(tokenStr) {
            return $._.$.security.__ca_verifyToken__(tokenStr);
        };

        that.isAuthorized = function(from, method, ignoreCaller,
                                     ignoreInternal) {
            if (!ignoreCaller) {
                caller = null;
            }
            if (from === json_rpc.SYSTEM_FROM) {
                if (!ignoreCaller) {
                    caller = from;
                }
                return true;
            }
            if (!ignoreInternal && (method.indexOf('__ca_') === 0)) {
                // only SYSTEM can call framework methods
                return false;
            }
            const fromArray = json_rpc.splitName(from);
            if (rules.isAuthorized(fromArray[0], fromArray[1], method, rE)) {
                if (!ignoreCaller) {
                    caller = from;
                }
                return true;
            }
            if (aggregates.isAuthorized(fromArray[0], fromArray[1], method,
                                        rEAggregates)) {
                if (!ignoreCaller) {
                    caller = from;
                }
                return true;
            }

            return false;
        };


        // Framework methods
        const super__ca_resume__ = myUtils.superior(that, '__ca_resume__');
        that.__ca_resume__ = function(cp, cb0) {
            //Backwards compatibility
            if (cp.acl && (!cp.state || !cp.state.acl)) {
                cp.state = cp.state || {};
                cp.state.acl = cp.acl;
            }

            super__ca_resume__(cp, function(err) {
                if (err) {
                    cb0(err);
                } else {
                    updateRules();
                    cb0(null);
                }
            });
        };

        const super__ca_begin__ = myUtils.superior(that, '__ca_begin__');
        that.__ca_begin__ = function(msg, cb0) {
            try {
                caller = null;
                if (json_rpc.isRequest(msg) || json_rpc.isNotification(msg)) {
                    const method = json_rpc.getMethodName(msg);
                    const from = json_rpc.getFrom(msg);
                    if (that.isAuthorized(from, method)) {
                        super__ca_begin__(msg, cb0);
                    } else {
                        const error = new Error('Not authorized');
                        error['code'] = json_rpc.ERROR_CODES.notAuthorized;
                        error['from'] = from;
                        error['method'] = method;
                        cb0(error);
                    }
                } else {
                    const error = new Error('Invalid message');
                    error['msg'] = msg;
                    cb0(error);
                }
            } catch (err) {
                // asume authorization error to avoid request replay.
                err.code = json_rpc.ERROR_CODES.notAuthorized;
                cb0(err);
            }
        };

        return [null, that];
    } catch (err) {
        return [err];
    }
};
