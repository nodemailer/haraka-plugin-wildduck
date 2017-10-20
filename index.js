/* eslint-env es6 */
/* globals DENY: false, OK: false, DENYSOFT: false */

'use strict';

// disable config loading by Wild Duck
process.env.DISABLE_WILD_CONFIG = 'true';

const db = require('./lib/db');
const DSN = require('./dsn');
const punycode = require('punycode');
const base32 = require('hi-base32');
const SRS = require('srs.js');
const crypto = require('crypto');
const counters = require('wildduck/lib/counters');
const tools = require('wildduck/lib/tools');

DSN.rcpt_too_fast = () =>
    DSN.create(
        450,
        '450-4.2.1 The user you are trying to contact is receiving mail at a rate that\nprevents additional messages from being delivered. Please resend your\nmessage at a later time. If the user is able to receive mail at that\ntime, your message will be delivered.',
        2,
        1
    );

exports.register = function() {
    let plugin = this;
    plugin.logdebug('Initializing rcpt_to Wild Duck plugin.');
    plugin.load_wildduck_ini();

    plugin.register_hook('init_master', 'init_wildduck_shared');
    plugin.register_hook('init_child', 'init_wildduck_shared');
};

exports.load_wildduck_ini = function() {
    let plugin = this;

    plugin.cfg = plugin.config.get(
        'wildduck.yaml',
        {
            booleans: ['accounts.createMissing', 'attachments.decodeBase64']
        },
        () => {
            plugin.load_wildduck_ini();
        }
    );
};

exports.open_database = function(server, next) {
    let plugin = this;

    plugin.srsRewriter = new SRS({
        secret: plugin.cfg.srs.secret
    });

    db.connect(server.notes.redis, plugin.cfg, (err, database) => {
        if (err) {
            return next(err);
        }
        plugin.db = database;
        plugin.ttlcounter = counters(database.redis).ttlcounter;
        plugin.loginfo('Database connection opened');
        next();
    });
};

exports.normalize_address = function(address) {
    if (/^SRS\d+=/i.test(address.user)) {
        // Try to fix case-mangled addresses where the intermediate MTA converts user part to lower case
        // and thus breaks hash verification
        let localAddress = address.user
            // ensure that address starts with uppercase SRS
            .replace(/^SRS\d+=/i, val => val.toUpperCase())
            // ensure that the first entity that looks like SRS timestamp is uppercase
            .replace(/([-=+][0-9a-f]{4})(=[A-Z2-7]{2}=)/i, (str, sig, ts) => sig + ts.toUpperCase());

        return localAddress + '@' + punycode.toUnicode(address.host.toLowerCase().trim());
    }

    return tools.normalizeAddress(address.address());
};

exports.init_wildduck_shared = function(next, server) {
    let plugin = this;

    plugin.open_database(server, next);
};

exports.hook_rcpt = function(next, connection, params) {
    let plugin = this;

    let rcpt = params[0];
    let address = plugin.normalize_address(rcpt);

    plugin.logdebug('Checking validity of ' + address);

    if (/^SRS\d+=/.test(address)) {
        let reversed = false;
        try {
            reversed = plugin.srsRewriter.reverse(address);
            let toDomain = punycode.toASCII(
                (reversed[1] || '')
                    .toString()
                    .toLowerCase()
                    .trim()
            );

            if (!toDomain) {
                plugin.logerror('SRS check failed for ' + address + '. Missing domain');
                return next(DENY, DSN.no_such_user());
            }

            reversed = reversed.join('@');
        } catch (E) {
            plugin.logerror('SRS check failed for ' + address + '. ' + E.message);
            return next(DENY, DSN.no_such_user());
        }

        if (reversed) {
            // accept SRS rewritten address
            return plugin.rateLimit(connection, 'rcpt', reversed, (err, success) => {
                if (err) {
                    return next(err);
                }

                if (!success) {
                    return next(DENYSOFT, DSN.rcpt_too_fast());
                }

                return next(OK);
            });
        }
    }

    let createAccount = () => {
        let domain = address.substr(address.lastIndexOf('@') + 1);

        if (!plugin.cfg.accounts.hosts.includes('*') && !plugin.cfg.accounts.hosts.includes(domain)) {
            plugin.logerror('Failed to create account for "' + address + '". Domain "' + domain + '" not allowed');
            return next(DENY, DSN.no_such_user());
        }

        let username = base32
            .encode(
                crypto
                    .createHash('md5')
                    .update(address.substr(0, address.indexOf('@')).replace(/\./g, '') + address.substr(address.indexOf('@')))
                    .digest()
            )
            .toLowerCase()
            .replace(/[=]+$/g, '');

        let userData = {
            username,
            address,
            recipients: Number(plugin.cfg.accounts.maxRecipients) || 0,
            forwards: Number(plugin.cfg.accounts.maxForwards) || 0,
            quota: Number(plugin.cfg.accounts.maxStorage || 0) * 1024 * 1024,
            retention: Number(plugin.cfg.accounts.retention) || 0,
            ip: connection.remote.ip
        };

        plugin.db.userHandler.create(userData, (err, id) => {
            if (err) {
                plugin.logerror('Failed to create account for "' + address + '". ' + err.message);
                return next(DENY, DSN.no_such_user());
            }
            plugin.loginfo('Created account for "' + address + '" with id "' + id + '"');

            return plugin.rateLimit(connection, 'rcpt', address, (err, success) => {
                if (err) {
                    return next(err);
                }

                if (!success) {
                    return next(DENYSOFT, DSN.rcpt_too_fast());
                }

                return next(OK);
            });
        });
    };

    plugin.db.userHandler.get(
        address,
        {
            quota: true,
            storageUsed: true,
            disabled: true
        },
        (err, userData) => {
            if (err) {
                return next(err);
            }

            if (!userData) {
                if (plugin.cfg.accounts.createMissing) {
                    return createAccount();
                }
                return next(DENY, DSN.no_such_user());
            }

            if (userData.disabled) {
                // user is disabled for whatever reason
                return next(DENY, DSN.mbox_disabled());
            }

            // max quota for the user
            let quota = userData.quota || Number(plugin.cfg.accounts.maxStorage || 0) * 1024 * 1024;

            if (userData.storageUsed && quota <= userData.storageUsed) {
                // can not deliver mail to this user, over quota
                return next(DENY, DSN.mbox_full());
            }

            next(OK);
        }
    );
};

exports.rateLimit = function(connection, key, value, next) {
    let plugin = this;

    let limit = plugin.cfg.limits[key];
    if (!limit) {
        return next(null, true);
    }
    let windowSize = plugin.cfg.limits[key + 'WindowSize'] || plugin.cfg.limits.windowSize || 1 * 3600 * 1000;

    plugin.ttlcounter('rl:' + key + ':' + value, 1, limit, windowSize, (err, result) => {
        if (err) {
            return next(err);
        }

        connection.logdebug(plugin, 'key=' + key + ' limit=' + limit + ' value=' + result.value + ' ttl=' + result.ttl);

        return next(null, result.success);
    });
};
