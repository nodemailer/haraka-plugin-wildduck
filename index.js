/* eslint-env es6 */
/* globals DENY: false, OK: false */

'use strict';

const mongodb = require('mongodb');
const MongoClient = mongodb.MongoClient;
const DSN = require('./dsn');
const punycode = require('punycode');
const SRS = require('srs.js');

exports.register = function() {
    let plugin = this;
    plugin.logdebug('Initializing rcpt_to Wild Duck plugin.');
    plugin.load_wildduck_ini();
};

exports.load_wildduck_ini = function() {
    let plugin = this;

    plugin.cfg = plugin.config.get(
        'wildduck.ini',
        {
            booleans: []
        },
        () => {
            plugin.load_wildduck_ini();
        }
    );
};

exports.open_database = function(next) {
    let plugin = this;

    plugin.srsRewriter = new SRS({
        secret: plugin.cfg.srs.secret
    });

    MongoClient.connect(plugin.cfg.mongo.url, (err, database) => {
        if (err) {
            return next(err);
        }
        plugin.database = database;
        plugin.usersdb = plugin.cfg.mongo.users ? database.db(plugin.cfg.mongo.users) : database;
        plugin.gridfsdb = plugin.cfg.mongo.gridfs ? database.db(plugin.cfg.mongo.gridfs) : database;
        next();
    });
};

exports.normalize_address = function(address) {
    let domain = address.host.toLowerCase().trim();

    if (/^SRS\d+=/i.test(address.user)) {
        // Try to fix case-mangled addresses where the intermediate MTA converts user part to lower case
        // and thus breaks hash verification
        let localAddress = address.user
            // ensure that address starts with uppercase SRS
            .replace(/^SRS\d+=/i, val => val.toUpperCase())
            // ensure that the first entity that looks like timestamp is uppercase
            .replace(/([-=+][0-9a-f]{4})(=[A-Z2-7]{2}=)/i, (str, sig, ts) => sig + ts.toUpperCase());

        return localAddress + '@' + punycode.toUnicode(domain);
    }

    let user = address.user
        // just in case it is an unicode username
        .normalize('NFC')
        // remove +label
        .replace(/\+.*$/, '')
        .toLowerCase()
        .trim();

    return user + '@' + punycode.toUnicode(domain);
};

exports.hook_init_master = function(next) {
    let plugin = this;

    plugin.open_database(next);
};

exports.hook_init_child = function(next) {
    let plugin = this;

    plugin.open_database(next);
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
            let toDomain = punycode.toASCII((reversed[1] || '').toString().toLowerCase().trim());

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
            return next(OK);
        }
    }

    // check if address exists
    plugin.usersdb.collection('addresses').findOne({
        addrview: address.substr(0, address.indexOf('@')).replace(/\./g, '') + address.substr(address.indexOf('@'))
    }, (err, addressObj) => {
        if (err) {
            return next(err);
        }
        if (!addressObj) {
            return next(DENY, DSN.no_such_user());
        }

        // load user for quota checks
        plugin.usersdb.collection('users').findOne({
            _id: addressObj.user
        }, {
            fields: {
                quota: true,
                storageUsed: true,
                disabled: true
            }
        }, (err, user) => {
            if (err) {
                return next(err);
            }

            if (!user) {
                return next(DENY, DSN.no_such_user());
            }

            if (user.disabled) {
                // user is disabled for whatever reason
                return next(DENY, DSN.mbox_disabled());
            }

            // max quota for the user
            let quota = user.quota || Number(plugin.cfg.maxStorage) * 1024;

            if (user.storageUsed && quota <= user.storageUsed) {
                // can not deliver mail to this user, over quota
                return next(DENY, DSN.mbox_full());
            }

            next(OK);
        });
    });
};
