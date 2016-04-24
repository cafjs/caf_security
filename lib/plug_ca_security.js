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
 * Security plug that authorizes method invocations for this CA.
 *
 * Decisions are based on the authenticated 'from' information in the request,
 * and an internal policy.
 *
 *
 *
 * @name caf_security/plug_ca_security
 * @namespace
 * @augments caf_components/gen_plug_ca
 *
 */
var assert = require('assert');
var caf_comp = require('caf_components');
var myUtils = caf_comp.myUtils;
var genPlugCA = caf_comp.gen_plug_ca;
var json_rpc = require('caf_transport').json_rpc;
var rules = require('./rules');
var aggregates = require('./aggregates');

/**
 * Factory method for an authorization plug for this CA.
 *
 * @see caf_components/supervisor
 */
exports.newInstance = function($, spec, cb) {
    try {

        /* Object.<id: string, caf.rule> */
        var acl = {};
        /* Compiled rules engine. */
        var rE = null;
        /* Ditto for aggregates engine*/
        var rEAggregates = null;

        var caller = null;

        var that = genPlugCA.constructor($, spec);

        assert.ok(Array.isArray(spec.env.defaultRules),
                  "'spec.env.defaultRules' is not an array.");

        that.computeRuleId = function(rule) {
            if (rule.type === rules.SIMPLE_RULE_TYPE) {
                return rules.computeRuleId(rule);
            } else if (rule.type === aggregates.AGGREGATE_RULE_TYPE) {
                return aggregates.computeRuleId(rule);
            } else {
                var err = new Error('Invalid rule type');
                err.rule = rule;
                throw err;
            }
        };

        spec.env.defaultRules.forEach(function(x) {
                                          acl[that.computeRuleId(x)] = x;
                                      });
        var caNameSplit = json_rpc.splitName($.ca.__ca_getName__());

        var updateRules = function() {
            var values = [];
            Object.keys(acl).forEach(function(x) { values.push(acl[x]);});
            var valuesSimple = values.filter(function(x) {
                return (x.type === rules.SIMPLE_RULE_TYPE);
            });
            rE = rules.newRuleEngine(caNameSplit[0], caNameSplit[1],
                                     valuesSimple);
            var valuesAgg =  values.filter(function(x) {
                return (x.type === aggregates.AGGREGATE_RULE_TYPE);
            });
            rEAggregates = aggregates.newRuleEngine($.ca, valuesAgg);
        };

        updateRules();

       // transactional ops
        var target = {
            addRuleImpl: function(newRule, cb0) {
                acl[that.computeRuleId(newRule)] = newRule;
                updateRules();
                cb0(null);
            },
            removeRuleImpl: function(ruleId, cb0) {
                delete acl[ruleId];
                updateRules();
                cb0(null);
            }
        };

        that.__ca_setLogActionsTarget__(target);

        that.addRule = function(newRule) {
            that.__ca_lazyApply__("addRuleImpl", [newRule]);
            return that.computeRuleId(newRule);
        };

        that.removeRule = function(ruleId) {
            that.__ca_lazyApply__("removeRuleImpl", [ruleId]);
        };

        that.listRules = function() {
            var result = myUtils.deepClone(acl);
            Object.freeze(result);
            return result;
        };

        that.getCallerFrom = function() {
            return caller;
        };

        /**
         * Gets the application name.
         *
         * @return {string} The application name.
         * @name  caf_security/__ca_getAppName__
         * @function
         */
        that.getAppName = function() {
            return $._.$.security.__ca_getAppName__();
        };

        that.attenuateToken = function(megaToken, constraints, cb0) {
            return $._.$.security.__ca_attenuateToken__(megaToken, constraints,
                                                        cb0);
        };

        that.verifyToken = function(tokenStr) {
            return  $._.$.security.__ca_verifyToken__(tokenStr);
        };

        that.isAuthorized = function(from, method, ignoreCaller) {
            if (!ignoreCaller) {
                caller = null;
            }
            if (from === json_rpc.SYSTEM_FROM) {
                if (!ignoreCaller) {
                    caller = from;
                }
                return true;
            }
            if (method.indexOf('__ca_') === 0) {
                // only SYSTEM can call framework methods
                return false;
            }
            var fromArray = json_rpc.splitName(from);
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
        var super__ca_resume__ = myUtils.superior(that, '__ca_resume__');
        that.__ca_resume__ = function(cp, cb0) {
            acl = cp.acl || {};
            updateRules();
            super__ca_resume__(cp, cb0);
        };

        var super__ca_begin__ = myUtils.superior(that, '__ca_begin__');
        that.__ca_begin__ = function(msg, cb0) {
            try {
                var error;
                caller = null;
                if (json_rpc.isRequest(msg) || json_rpc.isNotification(msg)) {
                    var method = json_rpc.getMethodName(msg);
                    var from = json_rpc.getFrom(msg);
                    if (that.isAuthorized(from, method)) {
                        super__ca_begin__(msg, cb0);
                    } else {
                        error = new Error('Not authorized');
                        error.code = json_rpc.ERROR_CODES.notAuthorized;
                        error.from = from;
                        error.method = method;
                        cb0(error);
                    }
                } else {
                    error = new Error('Invalid message');
                    error.msg = msg;
                    cb0(error);
                }
            } catch (err) {
                // asume authorization error to avoid request replay.
                err.code = json_rpc.ERROR_CODES.notAuthorized;
                cb0(err);
            }
        };

        var super__ca_prepare__ = myUtils.superior(that, '__ca_prepare__');
        that.__ca_prepare__ = function(cb0) {
            super__ca_prepare__(function(err, data) {
                                    if (err) {
                                        cb0(err, data);
                                    } else {
                                        data.acl = acl;
                                        cb0(err, data);
                                    }
                                });
        };

        cb(null, that);
    } catch (err) {
        cb(err);
    }
};
