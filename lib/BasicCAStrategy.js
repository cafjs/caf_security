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
 * A Passport strategy implementing basic password authentication for Cloud
 *  Assistants.
 *
 *
 */
var caf = require('caf_core');
var json_rpc = caf.json_rpc;

var util = require('util');
var passport = require('passport');
var assert = require('assert');
var sec_util = require('./util_security');

exports.handler = function(users) {
    return function(username, password, done) {
        if (users[username] === undefined) {
            done(null, false, { message: 'Unknown user' });
        } else if (!sec_util.verifyPasswordHash(password,
                                                users[username])) {
            done(null, false,
                 {message: 'Invalid password'});
        } else {
            done(null, username);
        }
    };
};

var Strategy = exports.Strategy = function(verify) {
    assert.ok(verify, 'basicCA authentication requires a verify function');
    passport.Strategy.call(this);
    this.name = 'basicCA';
    this._verify = verify;
};

util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the arguments of a CA method invocation, i.e.,
 * authenticate(username, password).
 *
 * @param {Object} req
 *
 */
Strategy.prototype.authenticate = function(req) {
    var self = this;
    var verified = function(err, user, info) {
        if (err) {
            self.error(err);
        } else if (!user) {
            self.fail(info);
        } else {
            self.success(user, info);
        }
    };
    var args = json_rpc.getMethodArgs(req.body);
    if (args && (args.length === 2)) {
        this._verify(args[0]/*username*/, args[1]/*password*/, verified);
    } else {
        this.fail('Missing credentials');
    }

};
