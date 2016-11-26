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
var caf = require('caf_core');
var json_rpc = caf.caf_transport.json_rpc;

var ADMIN_MAP = 'master';

var masterMap = function(self) {
    var name = self.__ca_getName__();
    return json_rpc.joinName(name, ADMIN_MAP);
};

var AUX_MAP = 'aux';

var auxMap = function(self) {
    var name = self.__ca_getName__();
    return json_rpc.joinName(name, AUX_MAP);
};



exports.methods = {
    "__ca_init__" : function(cb) {
        this.$.log.debug("++++++++++++++++Calling init");
        this.state.pulses = 0;
        this.$.sharing.addWritableMap('master', ADMIN_MAP);
        this.$.sharing.addReadOnlyMap('slave', masterMap(this),
                                      {isAggregate: true});
        this.$.sharing.addWritableMap('masterAux', AUX_MAP);
        this.$.sharing.addReadOnlyMap('slaveAux', auxMap(this));

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
    allowWithAggregate: function(method, name, cb) {
        var $$ = this.$.sharing.$;
        $$.master.set('__link_key__', [auxMap(this)]);
        $$.masterAux.set(name, true);
        var rule = this.$.security.newAggregateRule(method, 'slave');
        cb(null, this.$.security.addRule(rule));
    },
    denyWithAggregate: function(name, cb) {

        var $$ = this.$.sharing.$;
        $$.master.set('__link_key__', []);
        cb(null, null);
    },
    denyWithAggregateV2: function(name, cb) {
        var $$ = this.$.sharing.$;
        $$.masterAux.delete(name);
        cb(null, null);
    },
     query: function(name, cb) {
        var $$ = this.$.sharing.$;
        cb(null, $$.slave.getAll(name));
    }
};
