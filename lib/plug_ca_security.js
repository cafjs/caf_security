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
 * Decisions are based on the authenticated 'from' information in the request
 * and an internal policy.
 *
 * It should be defined in a ca.json description with name 'security_ca'.
 *
 *
 * @name caf_security/plug_ca_security
 * @namespace
 * @augments gen_transactional
  *
 */
var caf = require('caf_core');
var genTransactional = caf.gen_transactional;
var json_rpc = caf.json_rpc;

var allowOp = function(principal, method) {
    return {op: 'allow', principal: principal, method: method};
};

var denyOp = function(principal) {
    return {op: 'deny', principal: principal};
};

/**
 * Factory method to create a plug for this CA's authorization checks.
 *
 * @see sup_main
 */
exports.newInstance = function(context, spec, secrets, cb) {

    var $ = context;
    var logActions = [];

    // {principal{string} -> {(method{string} | '*') -> true}}
    var acl = {};
    var caller = null;

    var that = genTransactional.constructor(spec, secrets);

    var owner = secrets.myId.split('_')[0];

    var isAuthorized = function(method, from) {
        if (from === json_rpc.SYSTEM_FROM) {
            caller = from;
            return true;
        }
        if (method.indexOf('__ca_') === 0) {
            // only SYSTEM can call framework methods
            caller = null;
            return false;
        }
        var fromOwner = from.split('_')[0];
        if (owner === fromOwner) {
            caller = fromOwner;
            return true;
        }
        var perms = acl[fromOwner];
        if (perms && (perms['*'] || perms[method])) {
            caller = fromOwner;
            return true;
        }
        caller = null;
        return false;
    };

    that.getOwner = function() {
        return owner;
    };

    that.getCaller = function() {
        return caller;
    };

    that.allow = function(principal, method) {
        method = (method ? method : '*');
        logActions.push(allowOp(principal, method));
    };

    that.deny = function(principal) {
        logActions.push(denyOp(principal));
    };

    that.attenuateToken = function(megaToken, constraints, cb0) {
        return $.security_mux.attenuateToken(megaToken, constraints, cb0);
    };

    var replayLog = function() {
        logActions.forEach(function(action) {
                               switch (action.op) {
                               case 'allow':
                                   var perms = acl[action.principal] || {};
                                   perms[action.method] = true;
                                   acl[action.principal] = perms;
                                   break;
                               case 'deny':
                                   delete acl[action.principal];
                                   break;
                               default:
                                   throw new Error('CA Security: invalid log' +
                                                   ' action ' + action.op);
                               }
                           });
    };


    // Framework methods

    that.__ca_init__ = function(cb0) {
        logActions = [];
        cb0(null);
    };

    that.__ca_resume__ = function(cp, cb0) {
        cp = cp || {};
        logActions = cp.logActions || [];
        replayLog();
        cb0(null);
    };

    that.__ca_begin__ = function(msg, cb0) {
        var error = null;
        if (json_rpc.isRequest(msg) || json_rpc.isNotification(msg)) {
            var method = msg.method;
            var from = json_rpc.getFrom(msg);
            if (!isAuthorized(method, from)) {
                error = json_rpc.systemError(msg, json_rpc.ERROR_CODES
                                             .notAuthorized,
                                             'Access denied: From:' + from +
                                             ' method:' + method,
                                             secrets.myId);
            }
        } else {
            error = json_rpc.systemError(msg, json_rpc.ERROR_CODES
                                         .notAuthorized,
                                         'Not a valid request/notif',
                                         secrets.myId);
        }
        logActions = [];
        cb0(error);
    };

    that.__ca_prepare__ = function(cb0) {
        cb0(null, JSON.stringify({'logActions' : logActions}));
    };

    that.__ca_commit__ = function(cb0) {
        replayLog();
        caller = null;
        cb0(null);
    };

    that.__ca_abort__ = function(cb0) {
        logActions = [];
        caller = null;
        cb0(null);
    };

    cb(null, that);
};
