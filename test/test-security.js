
var caf_comp = require('caf_components');
var async = caf_comp.async;
var myUtils = caf_comp.myUtils;
var json_rpc = require('caf_transport').json_rpc;
var fs = require('fs');
var path = require('path');
var caf_security = require('../index.js');
var tokens = caf_security.tokens;
var rules = caf_security.rules;
var cli = require('caf_cli');


var hello = require('./hello/main.js');
var app = hello;

var HOST='localhost';
var PORT=3000;


var privKey1 = fs.readFileSync(path.resolve(__dirname,
                                            'hello/dummy1PrivKey.key'));
var privKey2 = fs.readFileSync(path.resolve(__dirname,
                                            'hello/dummy2PrivKey.key'));

var pubKey1 = fs.readFileSync(path.resolve(__dirname,
                                            'hello/dummy1PubKey.pem'));
var pubKey2 = fs.readFileSync(path.resolve(__dirname,
                                            'hello/dummy2SelfSigned.pem'));


var APP_PUBLISHER_1='someone1';
var APP_LOCAL_NAME_1='fooApp1';
var CA_OWNER_1='other1';
var CA_LOCAL_NAME_1='bar1';
var FROM_1 =  CA_OWNER_1 + '-' + CA_LOCAL_NAME_1;

var APP_PUBLISHER_2='someone2';
var APP_LOCAL_NAME_2='fooApp2';
var CA_OWNER_2='other2';
var CA_LOCAL_NAME_2='bar2';
var FROM_2 =  CA_OWNER_2 + '-' + CA_LOCAL_NAME_2;

var BAD_APP_PUBLISHER = 'some$one';

var APP_PUBLISHER_PUB_1 = "F1CD0B760DCEE7DE770249F4512A9D0A";
var APP_PUBLISHER_PUB_NAME_1 = "myApp";


process.on('uncaughtException', function (err) {
               console.log("Uncaught Exception: " + err);
               console.log(myUtils.errToPrettyStr(err));
               process.exit(1);

});

module.exports = {
    setUp: function (cb) {
       var self = this;
        app.init( {name: 'top'}, 'framework.json', null,
                      function(err, $) {
                          if (err) {
                              console.log('setUP Error' + err);
                              console.log('setUP Error $' + $);
                              // ignore errors here, check in method
                              cb(null);
                          } else {
                              self.$ = $;
                              cb(err, $);
                          }
                      });
    },

    tearDown: function (cb) {
        var self = this;
        if (!this.$) {
            cb(null);
        } else {
            this.$.top.__ca_graceful_shutdown__(null, cb);
        }
    },
    helloworld: function (test) {
        var self = this;
        test.expect(13);

        // signs ok
        var p1 = tokens.newPayload(APP_PUBLISHER_1, APP_LOCAL_NAME_1,
                                   CA_OWNER_1, CA_LOCAL_NAME_1, 10000);
        var p2 = tokens.newPayload(APP_PUBLISHER_2, APP_LOCAL_NAME_2,
                                   CA_OWNER_2, CA_LOCAL_NAME_2, 10000);
        var p1Signed = tokens.sign(p1, privKey1);
        var p2Signed = tokens.sign(p2, privKey2);

        var p1Ver = tokens.validate(p1Signed, pubKey1);
        test.ok(tokens.similar(p1Ver, p1));

        var p2Ver = tokens.validate(p2Signed, pubKey2);
        test.ok(tokens.similar(p2Ver, p2));

        test.ok(tokens.similar(tokens.decode(p1Signed), p1Ver));
        test.ok(tokens.similar(tokens.decode(p2Signed), p2Ver));


        // no signature
        test.throws(function() {tokens.validate(p1, pubKey1);});

        // bad pub key
        test.throws(function() {tokens.validate(p1Signed, pubKey2);});

        test.throws(function() {tokens.validate(p2Signed, pubKey1);});

        // tampered
        p1Signed = p1Signed + 'X';
        test.throws(function() {tokens.validate(p1Signed, pubKey1);});

        // badly formed
        p1.appPublisher = 32;
        var p1BadSigned = tokens.sign(p1, privKey1);
        test.throws(function() {tokens.validate(p1BadSigned, pubKey1);});

        p1.appPublisher = 'ooo-000';
        p1BadSigned = tokens.sign(p1, privKey1);
        test.throws(function() {tokens.validate(p1BadSigned, pubKey1);});

        // missing fields is ok
        delete p1.appPublisher;
        p1Signed = tokens.sign(p1, privKey1);
        test.ok(tokens.validate(p1Signed, pubKey1));



        // bad character in identifier
        test.throws(function() {
                        tokens.newPayload(BAD_APP_PUBLISHER, APP_LOCAL_NAME_2,
                                          CA_OWNER_2, CA_LOCAL_NAME_2, 10000);
                    });

        // expired token
        var pExpires = tokens.newPayload(APP_PUBLISHER_2, APP_LOCAL_NAME_2,
                                         CA_OWNER_2, CA_LOCAL_NAME_2, 1000);
        var p2SignedExpires = tokens.sign(pExpires, privKey2);
        setTimeout(function() {
                       test.throws(function() {
                                       tokens.validate(p2SignedExpires,
                                                       pubKey2);
                                   });
                       test.done();
                   }, 1500);
    },
    meet: function (test) {
        var self = this;
        test.expect(24);
        var p1 = tokens.newPayload(APP_PUBLISHER_1, APP_LOCAL_NAME_1,
                                   CA_OWNER_1, CA_LOCAL_NAME_1, 10000);
        var p2 = tokens.newPayload(null, APP_LOCAL_NAME_1,
                                   CA_OWNER_1, CA_LOCAL_NAME_1, 10000);
        var acl1 = tokens.newPayload(APP_PUBLISHER_1,null, CA_OWNER_1);
        test.ok(tokens.satisfyACL(acl1, p1));
        test.ok(tokens.satisfyACL(acl1, p2));

        var acl2 = tokens.newPayload(APP_PUBLISHER_1,null, CA_OWNER_2);
        test.ok(!tokens.satisfyACL(acl2, p1));
        test.ok(!tokens.satisfyACL(acl2, p2));
        test.ok(tokens.satisfyACL([acl2, acl1], p1));

        var aclAny =  tokens.newPayload();
        test.ok(tokens.satisfyACL(aclAny, p1));
        test.ok(tokens.satisfyACL(aclAny, p2));

        var aclNone = null;
        test.ok(!tokens.satisfyACL(aclNone, p1));
        test.ok(!tokens.satisfyACL(aclNone, p2));

        test.ok(tokens.lessOrEqual(p1, p2));
        test.ok(!tokens.lessOrEqual(p2, p1));

        // not comparable
        test.ok(!tokens.lessOrEqual(acl2, p2));
        test.ok(!tokens.lessOrEqual(p2, acl2));
        test.ok(!tokens.lessOrEqual(acl1, p2));
        test.ok(!tokens.lessOrEqual(p2, acl1));

        // reflexive, commutative, associative
        var p3 = tokens.newPayload(null, APP_LOCAL_NAME_1,
                                   CA_OWNER_1, null, 10000);
        var p4 = tokens.newPayload(APP_PUBLISHER_1, APP_LOCAL_NAME_1,
                                   null, CA_LOCAL_NAME_1, 10000);

        test.ok(tokens.similar(tokens.meet(p1, p1), p1));
        test.ok(tokens.similar(tokens.meet(p2, p2), p2));
        test.ok(tokens.similar(tokens.meet(p1, p2), tokens.meet(p2, p1)));
        test.ok(tokens.similar(tokens.meet(p3, p2), tokens.meet(p2, p3)));
        test.ok(tokens.similar(tokens.meet(p2, acl2), tokens.meet(acl2, p2)));
        test.ok(tokens.similar(tokens.meet(p1, null), tokens.meet(null, p1)));
        test.ok(tokens.similar(tokens.meet(p1, tokens.meet(p2, p3)),
                               tokens.meet(tokens.meet(p1, p2), p3)));
        console.log(tokens.meet(p1, tokens.meet(p2, p3)));
        test.ok(tokens.similar(tokens.meet(p2, tokens.meet(p3, p4)),
                               tokens.meet(tokens.meet(p2, p3), p4)));
        test.ok(tokens.similar(tokens.meet(p2, tokens.meet(p3, p4)),
                               tokens.meet(tokens.meet(p3, p2), p4)));


        test.done();
    },
    authentication : function (test) {
        var self = this;
        test.expect(12);
        var p1 = tokens.newPayload(APP_PUBLISHER_PUB_1,
                                   APP_PUBLISHER_PUB_NAME_1,
                                   CA_OWNER_1, CA_LOCAL_NAME_1, 100000);
        var p1Signed = tokens.sign(p1, privKey1);
        tokens.validate(p1Signed, pubKey1);
        var p2 = tokens.newPayload(APP_PUBLISHER_PUB_1,
                                   APP_PUBLISHER_PUB_NAME_1,
                                   null, CA_LOCAL_NAME_1, 100200);
        var p2Signed = tokens.sign(p2, privKey1);

        var p3 = tokens.newPayload(null, null, CA_OWNER_1, null, 100300);
        var p3Signed = tokens.sign(p3, privKey1);

        var p1Bad = tokens.newPayload(APP_PUBLISHER_PUB_1,
                                      APP_PUBLISHER_PUB_NAME_1,
                                      CA_OWNER_1, CA_LOCAL_NAME_2, 5000);
        var p1BadSigned = tokens.sign(p1Bad, privKey1);


        var weakerToken  = null;
        async.series(
            [
                function(cb) {
                    self.$._.$.security.__ca_authenticate__(FROM_1, p1Signed,
                                                            cb);
                },
                function(cb) {
                    self.$._.$.security.__ca_authenticate__(FROM_1, p2Signed,
                                                            cb);
                },
                function(cb) {
                    self.$._.$.security.__ca_authenticate__(FROM_1, p3Signed,
                                                            cb);
                },
                function(cb) {
                    // cached
                    self.$._.$.security.__ca_authenticate__(FROM_1, p1Signed,
                                                            cb);
                },

                // diffent local name
                function(cb) {
                    var cb1 = function(err, data) {
                        test.ok(err); // failed
                        console.log(err);
                        cb(null);
                    };
                    self.$._.$.security.__ca_authenticate__(FROM_1, p1BadSigned,
                                                            cb1);
                },
                function(cb) {
                    // cached
                    var cb1 = function(err, data) {
                        test.ok(err); // failed
                        test.equals(err.message,
                                    'Token does not respect constraints');
                        console.log(err);
                        setTimeout(function() {
                                       cb(null);
                                   }, 6000); // Enough for cron to clean cache
                    };
                    self.$._.$.security.__ca_authenticate__(FROM_1, p1BadSigned,
                                                          cb1);
                },
                function(cb) {
                    // should not be cached, and expire error instead
                    var cb1 = function(err, data) {
                        test.ok(err); // failed
                        test.equals(err.message, 'Invalid Token');
                        console.log(err);
                        console.log(err.message);
                        cb(null);
                    };
                    self.$._.$.security.__ca_authenticate__(FROM_1, p1BadSigned,
                                                          cb1);
                },


                // weaker token
                function(cb) {
                    var cb1 = function(err, data) {
                        test.ifError(err);
                        weakerToken = data;
                        cb(err, data);
                    };
                    var p1Constraint = myUtils.clone(p1);
                    p1Constraint.durationInMsec = 1000;
                    self.$._.$.security
                        .__ca_attenuateToken__(p3Signed, p1Constraint, cb1);
                },
                function(cb) {
                    self.$._.$.security.__ca_authenticate__(FROM_1, weakerToken,
                                                          cb);
                },

                // not a weaker token due to expire date
                function(cb) {
                    var cb1 = function(err, data) {
                        test.ok(err);
                        cb(null);
                    };
                    var p1Constraint = myUtils.clone(p1);
                    p1Constraint.durationInMsec = 10000000000000;
                    self.$._.$.security
                        .__ca_attenuateToken__(p3Signed, p1Constraint, cb1);
                },

                // not a weaker token because it never expires
                function(cb) {
                    var cb1 = function(err, data) {
                        test.ok(err);
                        cb(null);
                    };
                    var p1Constraint = myUtils.clone(p1);

                    self.$._.$.security
                        .__ca_attenuateToken__(p3Signed, p1Constraint, cb1);
                },

                // not a weaker token because of incompatible wildcard fields
                function(cb) {
                    var cb1 = function(err, data) {
                        test.ok(err);
                        cb(null);
                    };
                    var p2Constraint = myUtils.clone(p2);
                    p2Constraint.durationInMsec = 1000;
                    self.$._.$.security
                        .__ca_attenuateToken__(p3Signed, p2Constraint, cb1);
                },

                // 'nobody' account
                function(cb) {
                     self.$._.$.security
                        .__ca_authenticate__(json_rpc.DEFAULT_FROM, null, cb);
                },
                function(cb) {
                    var cb1 = function(err, data) {
                        test.ok(err);
                        cb(null);
                    };
                     self.$._.$.security
                        .__ca_authenticate__(FROM_1, null, cb1);
                },
                function(cb) {
                    var cb1 = function(err, data) {
                        test.ok(err);
                        cb(null);
                    };
                     self.$._.$.security
                        .__ca_authenticate__('donotwork', null, cb1);
                }
           ], function(err, data) {
               test.ifError(err);
               test.done();
           });
    },
    rules: function (test) {
        var self = this;
        test.expect(514);
        var rl = rules.newSimpleRule(null,rules.SELF, rules.CA_LOCAL) ;
        var r2 = rules.newSimpleRule(null,rules.SELF) ;
        var r3 = rules.newSimpleRule(); // anybody
        var r4 = rules.newSimpleRule(['barMethod'], rules.SELF,
                                     rules.CA_LOCAL);
        var r5 = rules.newSimpleRule('fooMethod', null,
                                     rules.CA_LOCAL);
        var r6 = r4;

        var r7 = rules.newSimpleRule(['fooMethod'], rules.SELF,
                                     rules.CA_LOCAL);

        var r8 = rules.newSimpleRule(['fooMethod', 'barMethod'], rules.SELF,
                                     rules.CA_LOCAL);

        var r9 =  rules.newSimpleRule('fooMethod', null, null);

        var r10 =  rules.newSimpleRule('fooMethod', rules.SELF, null);

        // ids unique and content-based
        var r7Id = rules.computeRuleId(r7);
        console.log(r7Id);
        var r8Id = rules.computeRuleId(r8);
        console.log(r8Id);

        test.ok( r7Id !== r8Id);
        test.ok( r7Id === rules.computeRuleId(r7));

        // simple rules
        var rE;
        var basicTest = function(ok1, ok2, ok3, ok4, ok5, ok6, ok7, ok8) {
            var errorMessage = function(owner, local, method, ruleEngine) {
                return owner + ':' + local + ':' + method + ':' +
                    JSON.stringify(ruleEngine);
            };

            test.ok(ok1 === rules.isAuthorized(CA_OWNER_1, CA_LOCAL_NAME_1,
                                               'fooMethod', rE),
                    errorMessage(CA_OWNER_1, CA_LOCAL_NAME_1, 'fooMethod', rE));

            test.ok(ok2 === rules.isAuthorized(CA_OWNER_2, CA_LOCAL_NAME_1,
                                               'fooMethod', rE),
                    errorMessage(CA_OWNER_2, CA_LOCAL_NAME_1, 'fooMethod', rE));

            test.ok(ok3 === rules.isAuthorized(CA_OWNER_1, CA_LOCAL_NAME_2,
                                               'fooMethod', rE),
                    errorMessage(CA_OWNER_1, CA_LOCAL_NAME_2, 'fooMethod', rE));

            test.ok(ok4 === rules.isAuthorized(CA_OWNER_2, CA_LOCAL_NAME_2,
                                               'fooMethod', rE),
                    errorMessage(CA_OWNER_2, CA_LOCAL_NAME_2, 'fooMethod', rE));

            test.ok(ok5 === rules.isAuthorized(CA_OWNER_1, CA_LOCAL_NAME_1,
                                               'barMethod', rE),
                    errorMessage(CA_OWNER_1, CA_LOCAL_NAME_1, 'barMethod', rE));

            test.ok(ok6 === rules.isAuthorized(CA_OWNER_2, CA_LOCAL_NAME_1,
                                               'barMethod', rE),
                    errorMessage(CA_OWNER_2, CA_LOCAL_NAME_1, 'barMethod', rE));

            test.ok(ok7 === rules.isAuthorized(CA_OWNER_1, CA_LOCAL_NAME_2,
                                               'barMethod', rE),
                    errorMessage(CA_OWNER_1, CA_LOCAL_NAME_2, 'barMethod', rE));

            test.ok(ok8 === rules.isAuthorized(CA_OWNER_2, CA_LOCAL_NAME_2,
                                               'barMethod', rE),
                    errorMessage(CA_OWNER_2, CA_LOCAL_NAME_2, 'barMethod', rE));

        };

        var testSet = [
            [CA_OWNER_1, CA_LOCAL_NAME_1, rl,
             [true, false, false, false, true, false, false, false ]],
            [CA_OWNER_1, CA_LOCAL_NAME_1, r2,
             [true, false, true, false, true, false, true, false]],
            [CA_OWNER_1, CA_LOCAL_NAME_1, r3,
             [true, true, true, true, true, true, true, true]],
            [CA_OWNER_1, CA_LOCAL_NAME_1, r4,
             [false, false, false, false, true, false, false, false ]],

            [CA_OWNER_1, CA_LOCAL_NAME_1, r5,
             [true, true, false, false, false, false, false, false ]],
            [CA_OWNER_1, CA_LOCAL_NAME_2, r6,
             [false, false, false, false, false, false, true, false]],
            [CA_OWNER_2, CA_LOCAL_NAME_1, r7,
             [false, true, false, false, false, false, false, false]],
            [CA_OWNER_1, CA_LOCAL_NAME_2, r8,
             [false, false, true, false, false, false, true, false ]],

            [CA_OWNER_1, CA_LOCAL_NAME_1, r9,
             [true, true, true, true, false, false, false, false]],
            [CA_OWNER_1, CA_LOCAL_NAME_1, r10,
             [true, false, true, false, false, false, false, false ]]

        ];

        var doOne = function() {
            testSet.forEach(function(x) {
                                rE = rules.newRuleEngine(x[0], x[1], [x[2]]);
                                console.log(rE);
                                basicTest.apply(this, x[3]);
                            });
        };

        doOne();
        // rules should compose
        // AuthorizedSet([rE1,  rE2]) = AuthorizedSet(rE1) + AuthorizedSet(rE2)

        var combine = function(x, y) {
            var result = [];
            for (var i = 0; i< x.length; i++) {
                result[i] = x[i] || y[i];
            }
            return result;
        };

        testSet
            .forEach(function(x) {
                         testSet
                             .forEach(function(y) {
                                          if ((x[0] === y[0]) &&
                                              (x[1] === y[1])) {
                                              rE = rules
                                                  .newRuleEngine(x[0], x[1],
                                                                 [x[2], y[2]]);

                                              console.log(rE);
                                              basicTest.apply(this,
                                                              combine(x[3],
                                                                      y[3]));
                                          }
                                      });
                     });
        test.done();
    },
    caAuthorization:  function (test) {
        var self = this;
        test.expect(11);
        var s1;
        var s2;
        var token1 = tokens.newPayload(APP_PUBLISHER_PUB_1,
                                       APP_PUBLISHER_PUB_NAME_1,
                                       CA_OWNER_1, CA_LOCAL_NAME_1, 10000);
        var tk1 =  tokens.sign(token1, privKey1);
        var from1 = CA_OWNER_1 + '-' + CA_LOCAL_NAME_1;

        var token2 = tokens.newPayload(APP_PUBLISHER_PUB_1,
                                       APP_PUBLISHER_PUB_NAME_1,
                                       CA_OWNER_2, CA_LOCAL_NAME_2, 10000);
        var tk2 =  tokens.sign(token2, privKey1);
        var from2 = CA_OWNER_2 + '-' + CA_LOCAL_NAME_2;
        var ruleId;

        async.waterfall(
            [
                function(cb) {
                    s1 = new cli.Session('ws://foo.vcap.me:3000', from1, {
                                            token : tk1,
                                            from : from1
                                        });
                    s1.onopen = function() {
                        s1.hello('foo', cb);
                    };
                },
                function(res, cb) {
                    test.equals(res, 'Bye:foo:' + from1);
                    s2 = new cli.Session('ws://foo.vcap.me:3000', from1, {
                                             token : tk2,
                                             from : from2
                                         });
                    s2.onclose = function(err) {
                        console.log(err);
                        test.ok(json_rpc.isSystemError(err));
                        test.equal(json_rpc.getSystemErrorCode(err),
                                   json_rpc.ERROR_CODES.notAuthorized);
                        cb(null, null);
                    };
                },
                function(res, cb) {
                    s1.allow(null,  CA_OWNER_2, CA_LOCAL_NAME_2, cb);
                },
                function(id, cb) {
                    test.equals(typeof id, 'string');
                    ruleId = id;
                    s2 = new cli.Session('ws://foo.vcap.me:3000', from1, {
                                             token : tk2,
                                             from : from2
                                         });
                     s2.onopen = function() {
                        s2.hello('foo', cb);
                    };
                },
                function(res, cb) {
                    test.equals(res, 'Bye:foo:'+ from2);
                    s2.listRules(cb);
                },
                function(all, cb) {
                    console.log(all);
                    test.equals(Object.keys(all).length, 2);
                    s1.removeRule(ruleId, cb);
                },
                function(res, cb) {
                    s1.attenuateToken(tk2,{ appPublisher : null,
                                            appLocalName : null,
                                            caOwner: null,
                                            caLocalName: null,
                                            durationInMsec: 1000 // shorter
                                          },
                                      cb);
                },
                function(res, cb) {
                    var tk2Shorter = tokens.validate(res, pubKey1);
                    console.log(tk2Shorter);
                    test.ok (tokens.lessOrEqual(tk2Shorter,token2));
                    s2.onclose = function(err) {
                        test.ok(json_rpc.isSystemError(err));
                        test.equal(json_rpc.getSystemErrorCode(err),
                               json_rpc.ERROR_CODES.notAuthorized);
                        cb(null, null);
                    };
                    var neverCalled = function() {
                        test.ok(false, 'should close session after auth error');
                    };
                    s2.hello('foo', neverCalled);
                },
                function(res, cb) {
                    s1.onclose = function(err) {
                        test.ifError(err);
                        cb(null, null);
                    };
                    s1.close();
                }
            ], function(err, res) {
                test.ifError(err);
                test.done();
            });
    }

};
