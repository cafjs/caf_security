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
"use strict";

exports.methods = {
    "__ca_init__" : function(cb) {
        this.$.log.debug("++++++++++++++++Calling init");
        this.state.pulses = 0;
        cb(null);
    },
    "__ca_resume__" : function(cp, cb) {
        this.$.log.debug("++++++++++++++++Calling resume: pulses=" +
                         this.state.pulses);

        cb(null);
    },
    "__ca_pulse__" : function(cb) {
        this.state.pulses = this.state.pulses + 1;
        this.$.log.debug('<<< Calling Pulse>>>' + this.state.pulses);
        cb(null);
    },
    hello: function(msg, cb) {
        this.state.lastMsg = msg;
        cb(null, 'Bye:' + msg + ':' + this.$.security.getCallerFrom());
    },
    allow: function(method, owner, localName, cb) {
        var rule = this.$.security.newSimpleRule(method,  owner, localName);
        cb(null, this.$.security.addRule(rule));
    },
    removeRule: function(ruleId, cb) {
        this.$.security.removeRule(ruleId);
        cb(null, null);
    },
    listRules : function(cb) {
        cb(null, this.$.security.listRules());
    },
    attenuateToken : function(megaToken, constraints, cb) {
        this.$.security.attenuateToken(megaToken, constraints, cb);
    },
    helloFail: function(msg, cb) {
        this.state.lastMsg = msg;
        var err = new Error('Something bad happened');
        cb(err);
    },
    helloException: function(msg, cb) {
        this.state.lastMsg = msg;
        var f = function() {
            var err = new Error('Something really bad happened');
            throw err;
        };
        f();
    },
    helloDelayException: function(msg, cb) {
        this.state.lastMsg = msg;
        var f = function() {
            var err = new Error('Something really bad happened');
            throw err;
        };
        setTimeout(f, 100);
    },
    getLastMessage: function(cb) {
        cb(null, this.state.lastMsg);
    },
    getQueueLength: function(cb) {
        cb(null, this.$.inq.queueLength());
    }
};

