'use strict';

const { PassThrough } = require('stream');

const { hookMail: authHookMail, hookDataPost: authHookDataPost } = require('./auth');

async function mail(plugin, connection, params) {
    const txn = connection.transaction;
    if (!txn) {
        return false;
    }

    let from = params[0];
    txn.notes.sender = from.address();

    plugin.loggelf({
        short_message: '[MAIL FROM:' + txn.notes.sender + '] ' + txn.uuid,

        _mail_action: 'mail_from',
        _from: txn.notes.sender,
        _queue_id: txn.uuid,
        _ip: connection.remote_ip,
        _proto: txn.notes.transmissionType
    });

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
