'use strict';

// Load modules

const Boom = require('boom');
const Hoek = require('hoek');


// Declare internals

const internals = {};


exports.register = function (plugin, options, next) {

    plugin.auth.scheme('ces', internals.implementation);
    next();
};


exports.register.attributes = {
    pkg: require('../package.json')
};


internals.implementation = function (server, options) {

    Hoek.assert(options, 'Missing ces auth strategy options');
    Hoek.assert(typeof options.validateFunc === 'function', 'options.validateFunc must be a valid function in ces scheme');

    const settings = Hoek.clone(options);

    const scheme = {
        authenticate: function (request, reply) {

            const state = request.state;


            settings.validateFunc(state, request, (err, isValid, credentials) => {

                credentials = credentials || null;

                if (err) {
                    return reply(err, null, { credentials: credentials });
                }

                if (!isValid) {
                    return reply(Boom.unauthorized('Bad user'),null, { credentials: credentials });
                }

                if (!credentials ||
                    typeof credentials !== 'object') {

                    return reply(Boom.badImplementation('Bad credentials object received for Basic auth validation'));
                }
                // Authenticated

                return reply.continue({ credentials: credentials });
            });
        }
    };

    return scheme;
};
