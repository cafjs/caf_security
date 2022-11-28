var caf = require('caf_core');
var caf_comp = caf.caf_components;
var json_rpc = caf.caf_transport.json_rpc;
var myUtils = caf_comp.myUtils;
var async = caf_comp.async;
var cli =  caf.caf_cli;

var fs = require('fs');
var path = require('path');
var caf_security = require('../index.js');
var tokens = caf_security.tokens;
var rules = caf_security.rules;
var aggregates = caf_security.aggregates;


var hello = require('./hello/main.js');
var app = hello;
var aggApp =  require('./aggregate/main.js');

//app = aggApp;


var HOST='localhost';
var PORT=3000;
var  privKey1 = fs.readFileSync(path.resolve(__dirname,
                                             'hello/dummy1PrivKey.key'));
var privKey2 = fs.readFileSync(path.resolve(__dirname,
                                            'hello/dummy2PrivKey.key'));

var pubKey1 = fs.readFileSync(path.resolve(__dirname,
                                           'hello/dummy1PubKey.pem'));
var pubKey2 = fs.readFileSync(path.resolve(__dirname,
                                           'hello/dummy2SelfSigned.pem'));


var APP_PUBLISHER_1='someone1';
var APP_LOCAL_NAME_1='fooapp1';
var CA_OWNER_1='other1';
var CA_LOCAL_NAME_1='bar1';
var FROM_1 =  CA_OWNER_1 + '-' + CA_LOCAL_NAME_1;

var APP_PUBLISHER_2='someone2';
var APP_LOCAL_NAME_2='fooapp2';
var CA_OWNER_2='other2';
var CA_LOCAL_NAME_2='bar2';
var FROM_2 =  CA_OWNER_2 + '-' + CA_LOCAL_NAME_2;


var CA_LOCAL_NAME_3='bar3';
var FROM_3 =  CA_OWNER_1 + '-' + CA_LOCAL_NAME_3;


var BAD_APP_PUBLISHER = 'some$one';

var APP_PUBLISHER_PUB_1 = "someone1";
var APP_PUBLISHER_PUB_NAME_1 = "fooapp1";

var PASSWD1 = 'foo';
var PASSWD2 = 'bar';

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
                                   CA_OWNER_1, CA_LOCAL_NAME_1, 10);
        var p2 = tokens.newPayload(APP_PUBLISHER_2, APP_LOCAL_NAME_2,
                                   CA_OWNER_2, CA_LOCAL_NAME_2, 10);
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
                              CA_OWNER_2, CA_LOCAL_NAME_2, 10);
        });

        // expired token
        var pExpires = tokens.newPayload(APP_PUBLISHER_2, APP_LOCAL_NAME_2,
                                         CA_OWNER_2, CA_LOCAL_NAME_2, 1);
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
                                   CA_OWNER_1, CA_LOCAL_NAME_1, 10);
        var p2 = tokens.newPayload(null, APP_LOCAL_NAME_1,
                                   CA_OWNER_1, CA_LOCAL_NAME_1, 10);
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
                                   CA_OWNER_1, null, 10);
        var p4 = tokens.newPayload(APP_PUBLISHER_1, APP_LOCAL_NAME_1,
                                   null, CA_LOCAL_NAME_1, 10);

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
                                   CA_OWNER_1, CA_LOCAL_NAME_1, 100);
        var p1Signed = tokens.sign(p1, privKey1);
        tokens.validate(p1Signed, pubKey1);
        var p2 = tokens.newPayload(APP_PUBLISHER_PUB_1,
                                   APP_PUBLISHER_PUB_NAME_1,
                                   null, CA_LOCAL_NAME_1, 101);
        var p2Signed = tokens.sign(p2, privKey1);

        var p3 = tokens.newPayload(null, null, CA_OWNER_1, null, 102);
        var p3Signed = tokens.sign(p3, privKey1);

        var p1Bad = tokens.newPayload(APP_PUBLISHER_PUB_1,
                                      APP_PUBLISHER_PUB_NAME_1,
                                      CA_OWNER_1, CA_LOCAL_NAME_2, 5);
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
                    p1Constraint.durationInSec = 1;
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
                    p1Constraint.durationInSec = 10000000000;
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
                    p2Constraint.durationInSec = 1;
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
    aggregates: function(test) {
        var map = {};
        var t1 = {};
        var t2 = {};
        var fakeAggregate = function(agg) {
            return {
                getAll: function(key) {
                    var res = agg[key];
                    return (res ? [res] : []);
                }
            };
        };
        map.friends = fakeAggregate(t1);
        map.work = fakeAggregate(t2);
        var fakeCA = { $ : {sharing : { $ : {proxy: { $ :map}}}}};
        test.expect(16);

        // work colleagues can do 'foo', 'bar' and 'foobar'
        var r1 = aggregates.newAggregateRule('foo', 'work');
        var r2 = aggregates.newAggregateRule(['bar', 'foobar'], 'work');
        test.equals( typeof  aggregates.computeRuleId(r1), 'string');
        test.ok(aggregates.computeRuleId(r1) !== aggregates.computeRuleId(r2));
        test.ok(aggregates.computeRuleId(r1) === aggregates.computeRuleId(r1));

        // friends can do anything
        var r3 = aggregates.newAggregateRule(null, 'friends');

        var rE = aggregates.newRuleEngine(fakeCA, [r1,r2,r3]);

        // John and Susan are friends, only one of Susan's CA enabled.
        t1['john'] = true;
        t1['susan-caX'] = true;

        // Mike and Helen are co-workers, only two Helen's CAs are enabled
        t2['mike'] = true;
        t2['helen-ca1'] = true;
        t2['helen-ca2'] = true;

        test.ok(aggregates.isAuthorized('john', 'caYY', 'm1', rE));
        test.ok(!aggregates.isAuthorized('susan', 'caNope', 'mXX', rE));

        test.ok(aggregates.isAuthorized('mike', 'caXX', 'foo', rE));
        test.ok(aggregates.isAuthorized('mike', 'caX', 'foobar', rE));
        test.ok(!aggregates.isAuthorized('mike', 'caXX', 'fooNever', rE));

        test.ok(aggregates.isAuthorized('helen', 'ca1', 'foo', rE));
        test.ok(aggregates.isAuthorized('helen', 'ca2', 'foobar', rE));
        test.ok(!aggregates.isAuthorized('helen', 'caXX', 'foo', rE));
        test.ok(!aggregates.isAuthorized('helen', 'ca1', 'fooNever', rE));
        test.ok(!aggregates.isAuthorized('helen', 'caXXX', 'fooNever', rE));

        // change aggregates
        delete t2['helen-ca1'];
        test.ok(!aggregates.isAuthorized('helen', 'ca1', 'foo', rE));
        t2['helen-ca1'] = true;
        test.ok(aggregates.isAuthorized('helen', 'ca1', 'foo', rE));

        // change rules
        rE = aggregates.newRuleEngine(fakeCA, [r2,r3]);
        test.ok(!aggregates.isAuthorized('helen', 'ca1', 'foo', rE));

        test.done();

    },
    caAuthorization:  function (test) {
        var self = this;
        test.expect(13);
        var s1;
        var s2;
        var token1 = tokens.newPayload(APP_PUBLISHER_1,
                                       APP_LOCAL_NAME_1,
                                       CA_OWNER_1, CA_LOCAL_NAME_1, 10);
        var tk1 =  tokens.sign(token1, privKey1);
        var from1 = CA_OWNER_1 + '-' + CA_LOCAL_NAME_1;

        var token2 = tokens.newPayload(APP_PUBLISHER_1,
                                       APP_LOCAL_NAME_1,
                                       CA_OWNER_2, CA_LOCAL_NAME_2, 10);
        var tk2 =  tokens.sign(token2, privKey1);
        var from2 = CA_OWNER_2 + '-' + CA_LOCAL_NAME_2;
        var ruleId;

        async.waterfall(
            [
                function(cb) {
                    s1 = new cli.Session('ws://someone1-fooapp1.localtest.me:3000', from1, {
                        token : tk1,
                        from : from1
                    });
                    s1.onopen = function() {
                        s1.hello('foo', cb);
                    };
                },
                function(res, cb) {
                    test.equals(res, 'Bye:foo:' + from1);
                    s2 = new cli.Session('ws://someone1-fooapp1.localtest.me:3000', from1, {
                        token : tk2,
                        from : from2
                    });
                    s2.onclose = function(err) {
                        console.log(err.msg);
                        test.ok(json_rpc.isSystemError(err.msg));
                        test.equal(json_rpc.getSystemErrorCode(err.msg),
                                   json_rpc.ERROR_CODES.notAuthorized);
                        cb(null, null);
                    };
                },
                // check only owners can create CAs
                function(res, cb) {
                    s2 = new cli.Session('ws://someone1-fooapp1.localtest.me:3000', from2, {
                        token : tk1,
                        from : from1
                    });
                    s2.onclose = function(err) {
                        console.log(err.msg);
                        test.ok(json_rpc.isSystemError(err.msg));
                        test.equal(json_rpc.getSystemErrorCode(err.msg),
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
                    s2 = new cli.Session('ws://someone1-fooapp1.localtest.me:3000', from1, {
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
                                            durationInSec: 1 // shorter
                                          },
                                      cb);
                },
                function(res, cb) {
                    var tk2Shorter = tokens.validate(res, pubKey1);
                    console.log(tk2Shorter);
                    test.ok (tokens.lessOrEqual(tk2Shorter,token2));
                    s2.onclose = function(err) {
                        test.ok(json_rpc.isSystemError(err.msg));
                        test.equal(json_rpc.getSystemErrorCode(err.msg),
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
                app = aggApp;
                test.done();
            });
    },
    aggAuthorization:  function (test) {
        var self = this;
        test.expect(13);
        var s1;
        var s2;
        var token1 = tokens.newPayload(APP_PUBLISHER_1,
                                       APP_LOCAL_NAME_1,
                                       CA_OWNER_1, CA_LOCAL_NAME_3, 1000);
        var tk1 =  tokens.sign(token1, privKey1);
        var from3 = CA_OWNER_1 + '-' + CA_LOCAL_NAME_3;

        var token2 = tokens.newPayload(APP_PUBLISHER_1,
                                       APP_LOCAL_NAME_1,
                                       CA_OWNER_2, CA_LOCAL_NAME_2, 1000);
        var tk2 =  tokens.sign(token2, privKey1);
        var from2 = CA_OWNER_2 + '-' + CA_LOCAL_NAME_2;
        var ruleId;

        async.waterfall(
            [
                function(cb) {
                    console.log('<1');
                    s1 = new cli.Session('ws://someone1-fooapp1.localtest.me:3000',
                                         from3, {
                        token : tk1,
                        from : from3
                    });
                    s1.onopen = function() {
                        s1.allowWithAggregate(['__external_ca_touch__',
                                               'hello'], from2, cb);
                    };
                },
                function(res, cb) {
                    console.log('<2');
                    test.equals(typeof res, 'string');
                    setTimeout(function() {
                        s1.query(from2, function(err, data) {
                            test.ifError(err);
                            test.equals(data.length, 1);
                            console.log('<<<>><><>>' + data);
                            cb(null, data);
                        });
                    }, 2000);
                },
                function(res, cb) {
                    console.log('<3');
                    s2 = new cli.Session('ws://someone1-fooapp1.localtest.me:3000',
                                         from3, {
                                             token : tk2,
                                             from : from2
                                         });
                    s2.onopen = function() {
                        s2.hello('foo', cb);
                    };
                },
                function(res, cb) {
                    console.log('<4');
                    test.equals(res, 'Bye:foo:' + from2);
                    cb(null, null);
                },
                function(res, cb) {
                    console.log('<5');
                    s1.denyWithAggregate(from2, cb);
                },
                function(res, cb) {
                    console.log('<6');
                    setTimeout(function() {
                        s1.query(from2, function(err, data) {
                            test.ifError(err);
                            test.equals(data.length, 0);
                            console.log('<<<>><><>>' + data);
                            cb(null, data);
                        });
                    }, 2000);
                },

                function(res, cb) {
                    console.log('<7');
                    var cb1 = function(err, data) {
                        // never reached
                        test.ok(false);
                        cb(null, null);
                    };
                    s2.onclose = function(err) {
                        test.ok(err);
                        cb(null, null);
                    };
                    s2.hello('foo', cb1);
                },
                function(res, cb) {
                    console.log('<8');
                    s1.allowWithAggregate(['__external_ca_touch__',
                                           'hello'], from2, cb);
                },
                function(res, cb) {
                    console.log('<9');
                    setTimeout(function() {
                        s2 = new cli.Session('ws://someone1-fooapp1.localtest.me:3000',
                                             from3, {
                                                 token : tk2,
                                                 from : from2
                                             });
                        s2.onclose = function(err) {
                            // never reached
                            test.ok(false);
                            // cleanup
                            s1.onclose = function() {};
                            s1.close();
                            cb(err);
                        };
                        s2.onopen = function() {
                            s2.hello('foo', cb);
                        };
                    }, 2000); // leave enough time to propagate aggregate
                },
                function(res, cb) {
                    console.log('<10');
                    test.equals(res, 'Bye:foo:' + from2);
                    cb(null, null);
                },
                function(res, cb) {
                    console.log('<11');
                    s1.denyWithAggregateV2(from2, cb);
                },
                function(res, cb) {
                    console.log('<12');
                    setTimeout(function() {
                        s1.query(from2, function(err, data) {
                            test.ifError(err);
                            test.equals(data.length, 0);
                            console.log('<<<>><><>>' + data);
                            cb(null, data);
                        });
                    }, 2000);
                },
                function(res, cb) {
                    console.log('<13');
                    var cb1 = function(err, data) {
                        // never reached
                        console.log('7error:' + err);
                        console.log('7data:' + data);
                        test.ok(false);
                        s2.onclose = function() {};
                        s2.close();
                        cb(null, null);
                    };
                    s2.onclose = function(err) {
                        test.ok(err);
                        cb(null, null);
                    };
                    s2.hello('foo', cb1);
                },
                function(res, cb) {
                    console.log('<14');
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
