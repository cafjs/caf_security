var caf = require('caf_core');

exports.init = function(spec, frameworkDesc, modules, cb) {
    modules = modules || [];
    if (modules && !Array.isArray(modules)) {
        modules = [modules];
    }
    modules.push(module);
    caf.init(modules, spec, frameworkDesc, cb);
};

