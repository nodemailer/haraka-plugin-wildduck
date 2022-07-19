/* globals DENYSOFT: false */

'use strict';

const { PassThrough } = require('stream');
const ObjectId = require('mongodb').ObjectId;

const { hookMail: authHookMail, hookDataPost: authHookDataPost } = require('./auth');

async function mail(plugin, connection, params) {
    const txn = connection.transaction;
    if (!txn) {
        return false;
    }

    let from = params[0];
    txn.notes.sender = from.address();

    txn.notes.id = new ObjectId();
    txn.notes.rateKeys = [];
    txn.notes.targets = {
        users: new Map(),
        forwards: new Map(),
        recipients: new Set(),
        autoreplies: new Map()
    };

    txn.notes.transmissionType = []
        .concat(connection.greeting === 'EHLO' ? 'E' : [])
        .concat('SMTP')
        .concat(connection.tls_cipher ? 'S' : [])
        .join('');

    plugin.loggelf({
        short_message: '[MAIL FROM:' + txn.notes.sender + '] ' + txn.uuid,

        _mail_action: 'mail_from',
        _from: txn.notes.sender,
        _queue_id: txn.uuid,
        _ip: connection.remote_ip,
        _proto: txn.notes.transmissionType
    });

    let settings;
    try {
        settings = await plugin.db.settingsHandler.getMulti(['const:max:storage', 'const:max:recipients', 'const:max:forwards']);
    } catch (err) {
        plugin.logerror(err, plugin, connection);
        txn.notes.rejectCode = 'ERRC04';

        let smtpErr = new Error('Failed to process address, try again [ERRC04]');
        smtpErr.smtpAction = DENYSOFT;
        throw smtpErr;
    }

    txn.notes.settings = settings;

    // SPF check
    await authHookMail(plugin, connection, params);
}

function dataPost(next, plugin, connection) {
    const txn = connection?.transaction;
    if (!txn) {
        return next();
    }

    const stream = new PassThrough();
    authHookDataPost(stream, plugin, connection)
        .then(() => {
            next();
        })
        .catch(err => {
            plugin.logerror(err, plugin, connection);
            next();
        });

    txn.message_stream.pipe(stream, { line_endings: '\r\n' });
}

module.exports = { mail, dataPost };
