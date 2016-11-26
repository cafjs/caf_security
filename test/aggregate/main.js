var caf = require('caf_core');
var caf_comp = caf.caf_components;
var caf_platform = caf.caf_platform;
var caf_ca = caf.caf_ca;

exports.init = function(spec, frameworkDesc, modules, cb) {
    var cb0 = function(err, $) {
         if (cb) {
            cb(err, $);
        } else {
            if (err) {
                console.log('Got error ' + myUtils.errToPrettyStr(err));
                process.exit(1);
            } else {
                $._.$.log && $._.$.log.debug('READY P5JGqWGXOzqOFg ');
            }
        }
    };

    modules = modules || [];
    if (modules && !Array.isArray(modules)) {
        modules = [modules];
    }
    modules.push(module);
    modules.push(caf_platform.getModule());
    modules.push(caf_ca.getModule());

    caf_comp.load(null, spec, frameworkDesc, modules, cb0);
};
