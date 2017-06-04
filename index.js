/* eslint-env es6 */
/* globals DENY: false, OK: false */

'use strict';

const mongodb = require('mongodb');
const MongoClient = mongodb.MongoClient;
const DSN = require('Haraka/dsn');
const punycode = require('punycode');

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

    MongoClient.connect(plugin.cfg.mongo.url, (err, database) => {
        if (err) {
            return next(err);
        }
        plugin.database = database;
        next();
    });
};

exports.normalize_address = function(address) {
    let user = address.user
        // just in case it is an unicode username
        .normalize('NFC')
        // remove +label
        .replace(/\+.*$/, '')
        .toLowerCase()
        .trim();

    let domain = address.host.toLowerCase().trim();

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

    // check if address exists
    plugin.database.collection('addresses').findOne({
        address
    }, (err, addressObj) => {
        if (err) {
            return next(err);
        }
        if (!addressObj) {
            return next(DENY, DSN.no_such_user());
        }

        // load user for quota checks
        plugin.database.collection('users').findOne({
            _id: addressObj.user
        }, {
            fields: {
                quota: true,
                storageUsed: true
            }
        }, (err, user) => {
            if (err) {
                return next(err);
            }

            if (!user) {
                return next(DENY, DSN.no_such_user());
            }

            if (user.quota && user.storageUsed && user.quota <= user.storageUsed) {
                // can not deliver mail to this user
                return next(DENY, DSN.mbox_full());
            }

            next(OK);
        });
    });
};
