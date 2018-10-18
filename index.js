/* eslint-env es6 */
/* globals DENY: false, OK: false, DENYSOFT: false */

'use strict';

// disable config loading by Wild Duck
process.env.DISABLE_WILD_CONFIG = 'true';

const os = require('os');
const ObjectID = require('mongodb').ObjectID;
const db = require('./lib/db');
const DSN = require('./dsn');
const punycode = require('punycode');
const SRS = require('srs.js');
const counters = require('wildduck/lib/counters');
const tools = require('wildduck/lib/tools');
const StreamCollect = require('./lib/stream-collect');
const Maildropper = require('wildduck/lib/maildropper');
const FilterHandler = require('wildduck/lib/filter-handler');
const autoreply = require('wildduck/lib/autoreply');
const consts = require('wildduck/lib/consts');
const Gelf = require('gelf');

DSN.rcpt_too_fast = () =>
    DSN.create(
        450,
        '450-4.2.1 The user you are trying to contact is receiving mail at a rate that\nprevents additional messages from being delivered. Please resend your\nmessage at a later time. If the user is able to receive mail at that\ntime, your message will be delivered.',
        2,
        1
    );

exports.register = function() {
    let plugin = this;
    plugin.logdebug('Initializing rcpt_to Wild Duck plugin.', plugin);
    plugin.load_wildduck_ini();

    plugin.register_hook('init_master', 'init_wildduck_shared');
    plugin.register_hook('init_child', 'init_wildduck_shared');
};

exports.load_wildduck_ini = function() {
    let plugin = this;

    plugin.cfg = plugin.config.get(
        'wildduck.yaml',
        {
            booleans: ['attachments.decodeBase64', 'sender.enabled']
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

    plugin.hostname = (plugin.cfg.gelf && plugin.cfg.gelf.hostname) || os.hostname();
    plugin.gelf =
        plugin.cfg.gelf && plugin.cfg.gelf.enabled
            ? new Gelf(plugin.cfg.gelf.options)
            : {
                  // placeholder
                  emit: () => false
              };

    plugin.loggelf = message => {
        if (typeof message === 'string') {
            message = {
                short_message: message
            };
        }
        message = message || {};
        message.facility = 'mx'; // facility is deprecated but set by the driver if not provided
        message.host = plugin.hostname;
        message.timestamp = Date.now() / 1000;
        message._component = 'mx';

        Object.keys(message).forEach(key => {
            if (!message[key]) {
                delete message[key];
            }
        });
        plugin.gelf.emit('gelf.log', message);
    };

    db.connect(
        server.notes.redis,
        plugin.cfg,
        (err, db) => {
            if (err) {
                return next(err);
            }
            plugin.db = db;
            plugin.ttlcounter = counters(db.redis).ttlcounter;

            plugin.maildrop = new Maildropper({
                db,
                enabled: plugin.cfg.sender.enabled,
                zone: plugin.cfg.sender.zone,
                collection: plugin.cfg.sender.collection,
                gfs: plugin.cfg.sender.gfs
            });

            let spamChecks = plugin.cfg.spamHeaders && tools.prepareSpamChecks(plugin.cfg.spamHeaders);

            plugin.filterHandler = new FilterHandler({
                db,
                sender: plugin.cfg.sender,
                messageHandler: plugin.db.messageHandler,
                spamChecks,
                spamHeaderKeys: spamChecks && spamChecks.map(check => check.key),
                spamScoreValue: plugin.cfg.spamScore,
                loggelf: message => plugin.loggelf(message)
            });

            plugin.loginfo('Database connection opened', plugin);
            next();
        }
    );
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

exports.hook_mail = function(next, connection, params) {
    let plugin = this;

    let from = params[0];
    connection.transaction.notes.sender = from.address();

    connection.transaction.notes.id = new ObjectID();
    connection.transaction.notes.rateKeys = [];
    connection.transaction.notes.targets = {
        users: new Map(),
        forwards: new Map(),
        recipients: new Set(),
        autoreplies: new Map()
    };

    connection.transaction.notes.transmissionType = []
        .concat(connection.greeting === 'EHLO' ? 'E' : [])
        .concat('SMTP')
        .concat(connection.tls_cipher ? 'S' : [])
        .join('');

    plugin.loggelf({
        short_message: 'MX SMTP [MAIL FROM:' + connection.transaction.notes.sender + '] ' + connection.transaction.uuid,

        _mail_action: 'mail_from',
        _from: connection.transaction.notes.sender,
        _queue_id: connection.transaction.uuid,
        _ip: connection.remote_ip,
        _proto: connection.transaction.notes.transmissionType
    });

    return next();
};

exports.hook_rcpt = function(next, connection, params) {
    let plugin = this;

    const { recipients, forwards, autoreplies, users } = connection.transaction.notes.targets;

    let rcpt = params[0];
    if (/\*/.test(rcpt.user)) {
        // Using * is not allowed in addresses
        return next(DENY, DSN.no_such_user());
    }

    let address = plugin.normalize_address(rcpt);

    recipients.add(address);

    let resolution = false;
    let hookDone = (...args) => {
        if (resolution) {
            let message = {
                short_message: 'MX SMTP [RCPT TO:' + rcpt.address() + '] ' + connection.transaction.uuid,
                _mail_action: 'rpt_to',
                _to: rcpt.address(),
                _queue_id: connection.transaction.uuid,
                _ip: connection.remote_ip,
                _proto: connection.transaction.notes.transmissionType
            };

            Object.keys(resolution).forEach(key => {
                if (resolution[key]) {
                    message[key] = resolution[key];
                }
            });

            plugin.loggelf(message);
        }
        next(...args);
    };

    plugin.logdebug('Checking validity of ' + address, plugin, connection);

    if (/^SRS\d+=/.test(address)) {
        let reversed = false;
        try {
            reversed = plugin.srsRewriter.reverse(address.substr(0, address.indexOf('@')));
            let toDomain = punycode.toASCII(
                (reversed[1] || '')
                    .toString()
                    .toLowerCase()
                    .trim()
            );

            if (!toDomain) {
                plugin.logerror('SRS FAILED rcpt=' + address + ' error=Missing domain', plugin, connection);
                resolution = {
                    _srs: 'yes',
                    _error: 'missing domain'
                };
                return hookDone(DENY, DSN.no_such_user());
            }

            reversed = reversed.join('@');
        } catch (err) {
            plugin.logerror('SRS FAILED rcpt=' + address + ' error=' + err.message, plugin, connection);
            resolution = {
                full_message: err.stack,
                _srs: 'yes',

                _failure: 'yes',
                _error: 'srs check failed',
                _err_code: err.code
            };
            return hookDone(DENY, DSN.no_such_user());
        }

        if (reversed) {
            // accept SRS rewritten address
            let key = reversed;
            let selector = 'rcpt';
            return plugin.checkRateLimit(connection, selector, key, false, (err, success) => {
                if (err) {
                    resolution = {
                        full_message: err.stack,
                        _srs: 'yes',
                        _rate_limit: 'yes',
                        _selector: selector,

                        _failure: 'yes',
                        _error: 'rate limit check failed',
                        _err_code: err.code
                    };
                    return hookDone(err);
                }

                if (!success) {
                    resolution = {
                        _srs: 'yes',
                        _rate_limit: 'yes',
                        _selector: selector,
                        _error: 'too many attempts'
                    };
                    return hookDone(DENYSOFT, DSN.rcpt_too_fast());
                }

                // update rate limit for this address after delivery
                connection.transaction.notes.rateKeys.push({ selector, key });

                plugin.loginfo('SRS USING rcpt=' + address + ' target=' + reversed, plugin, connection);

                forwards.set(reversed, { type: 'mail', value: reversed });

                resolution = {
                    _srs: 'yes',
                    _resolved: reversed
                };
                return hookDone(OK);
            });
        }
    }

    let handleForwardingAddress = addressData => {
        plugin.ttlcounter(
            'wdf:' + addressData._id.toString(),
            addressData.targets.length,
            addressData.forwards || consts.MAX_FORWARDS,
            false,
            (err, result) => {
                if (err) {
                    // failed checks
                    resolution = {
                        full_message: err.stack,
                        _forward: 'yes',
                        _rate_limit: 'yes',
                        _selector: 'user',

                        _failure: 'yes',
                        _error: 'rate limit check failed',
                        _err_code: err.code
                    };
                    return hookDone(err);
                } else if (!result.success) {
                    connection.lognotice(
                        'RATELIMITED target=' +
                            addressData.address +
                            ' key=' +
                            addressData._id +
                            ' limit=' +
                            addressData.forwards +
                            ' value=' +
                            result.value +
                            ' ttl=' +
                            result.ttl,
                        plugin,
                        connection
                    );

                    resolution = {
                        _forward: 'yes',
                        _rate_limit: 'yes',
                        _selector: 'user',
                        _error: 'too many attempts'
                    };
                    return hookDone(DENYSOFT, DSN.rcpt_too_fast());
                }

                plugin.loginfo(
                    'FORWARDING rcpt=' +
                        address +
                        ' address=' +
                        addressData.address +
                        '[' +
                        addressData._id +
                        ']' +
                        ' target=' +
                        addressData.targets.map(target => ((target && target.value) || target).toString().replace(/\?.*$/, '')).join(','),
                    plugin,
                    connection
                );

                if (addressData.autoreply) {
                    autoreplies.set(addressData.addrview, addressData);
                }

                let forwardTargets = [];
                let pos = 0;
                let processTarget = () => {
                    if (pos >= addressData.targets.length) {
                        resolution = {
                            _forward: 'yes',
                            _resolved: forwardTargets.join('\n') || 'empty_list'
                        };
                        return hookDone(OK);
                    }

                    let targetData = addressData.targets[pos++];

                    if (targetData.type === 'relay') {
                        // relay is not rate limited
                        targetData.recipient = rcpt.address();
                        forwards.set(targetData.value, targetData);

                        forwardTargets.push(rcpt.address() + ':' + (targetData.value || '').toString().replace(/\?.*$/, ''));
                        return setImmediate(processTarget);
                    }

                    if (targetData.type === 'http' || (targetData.type === 'mail' && !targetData.user)) {
                        if (targetData.type !== 'mail') {
                            forwardTargets.push(rcpt.address() + ':' + targetData.value);
                            targetData.recipient = rcpt.address();
                        } else {
                            forwardTargets.push(targetData.value);
                        }

                        forwards.set(targetData.value, targetData);
                        return setImmediate(processTarget);
                    }

                    if (targetData.type !== 'mail') {
                        // no idea what to do here, some new feature probably
                        return setImmediate(processTarget);
                    }

                    if (targetData.user && users.has(targetData.user.toString())) {
                        // already listed as a recipient
                        return setImmediate(processTarget);
                    }

                    // we have a target user, so we need to resolve user data
                    plugin.db.users.collection('users').findOne(
                        { _id: targetData.user },
                        {
                            // extra fields are needed later in the filtering step
                            projection: {
                                _id: true,
                                name: true,
                                address: true,
                                forwards: true,
                                targets: true,
                                autoreply: true,
                                encryptMessages: true,
                                encryptForwarded: true,
                                pubKey: true,
                                spamLevel: true,
                                storageUsed: true,
                                quota: true
                            }
                        },
                        (err, userData) => {
                            if (err) {
                                err.code = 'InternalDatabaseError';
                                resolution = {
                                    full_message: err.stack,
                                    _collection: 'users',
                                    _db_query: '_id:' + targetData.user,

                                    _error: 'failed to make a db query',
                                    _failure: 'yes',
                                    _err_code: err.code
                                };
                                return hookDone(err);
                            }

                            if (!userData) {
                                // unknown user, treat as normal forward
                                targetData.recipient = rcpt.address();
                                forwards.set(targetData.value, targetData);
                                forwardTargets.push(rcpt.address());
                                return setImmediate(processTarget);
                            }

                            if (userData.disabled) {
                                // disabled user, skip
                                forwardTargets.push(rcpt.address() + ':disabled');
                                return setImmediate(processTarget);
                            }

                            // max quota for the user
                            let quota = userData.quota || consts.MAX_STORAGE;
                            if (userData.storageUsed && quota <= userData.storageUsed) {
                                // can not deliver mail to this user, over quota, skip
                                forwardTargets.push(rcpt.address() + ':over_quota');
                                return setImmediate(processTarget);
                            }

                            users.set(userData._id.toString(), {
                                userData,
                                recipient: rcpt.address()
                            });

                            forwardTargets.push(rcpt.address() + ':' + userData._id);

                            setImmediate(processTarget);
                        }
                    );
                };

                setImmediate(processTarget);
            }
        );
    };

    plugin.db.userHandler.resolveAddress(
        address,
        {
            wildcard: true,
            projection: {
                name: true,
                address: true,
                addrview: true,
                autoreply: true,
                targets: true // only forwarded address has `targets` set
            }
        },
        (err, addressData) => {
            if (err) {
                resolution = {
                    full_message: err.stack,
                    _api: 'resolveAddress',
                    _db_query: 'address:' + address,

                    _error: 'failed to resolve an address',
                    _failure: 'yes',
                    _err_code: err.code
                };
                return hookDone(err);
            }

            if (addressData && addressData.targets) {
                return handleForwardingAddress(addressData);
            }

            if (!addressData || !addressData.user) {
                plugin.logdebug('No such user ' + address, plugin, connection);
                resolution = {
                    _error: 'no such user',
                    _unknwon_user: 'yes'
                };
                return hookDone(DENY, DSN.no_such_user());
            }

            plugin.db.userHandler.get(
                addressData.user,
                {
                    // extra fields are needed later in the filtering step
                    name: true,
                    address: true,
                    forwards: true,
                    targets: true,
                    autoreply: true,
                    encryptMessages: true,
                    encryptForwarded: true,
                    pubKey: true,
                    spamLevel: true,
                    storageUsed: true,
                    quota: true
                },
                (err, userData) => {
                    if (err) {
                        resolution = {
                            full_message: err.stack,
                            _api: 'getUser',
                            _db_query: 'user:' + addressData.user,

                            _error: 'failed to fetch user',
                            _failure: 'yes',
                            _err_code: err.code
                        };
                        return hookDone(err);
                    }

                    if (!userData) {
                        resolution = {
                            _error: 'no such user',
                            _unknwon_user: 'yes'
                        };
                        return hookDone(DENY, DSN.no_such_user());
                    }

                    if (userData.disabled) {
                        // user is disabled for whatever reason
                        resolution = {
                            _user: userData._id.toString(),
                            _error: 'disabled user',
                            _disabled_user: 'yes'
                        };
                        return hookDone(DENY, DSN.mbox_disabled());
                    }

                    // max quota for the user
                    let quota = userData.quota || consts.MAX_STORAGE;

                    if (userData.storageUsed && quota <= userData.storageUsed) {
                        // can not deliver mail to this user, over quota
                        resolution = {
                            _user: userData._id.toString(),
                            _error: 'user over quota',
                            _over_quota: 'yes'
                        };
                        return hookDone(DENY, DSN.mbox_full());
                    }

                    let checkIpRateLimit = done => {
                        if (!connection.remote.ip) {
                            return done();
                        }

                        let key = connection.remote.ip + ':' + userData._id.toString();
                        let selector = 'rcptIp';
                        plugin.checkRateLimit(connection, selector, key, false, (err, success) => {
                            if (err) {
                                resolution = {
                                    full_message: err.stack,
                                    _rate_limit: 'yes',
                                    _selector: selector,

                                    _error: 'rate limit check failed',
                                    _failure: 'yes',
                                    _err_code: err.code
                                };
                                return hookDone(err);
                            }

                            if (!success) {
                                resolution = {
                                    _rate_limit: 'yes',
                                    _selector: selector,
                                    _error: 'too many attempts'
                                };
                                return hookDone(DENYSOFT, DSN.rcpt_too_fast());
                            }

                            // update rate limit for this address after delivery
                            connection.transaction.notes.rateKeys.push({ selector, key });

                            return done();
                        });
                    };

                    checkIpRateLimit(() => {
                        let key = userData._id.toString();
                        let selector = 'rcpt';
                        plugin.checkRateLimit(connection, selector, key, userData.receivedMax, (err, success) => {
                            if (err) {
                                resolution = {
                                    full_message: err.stack,
                                    _rate_limit: 'yes',
                                    _selector: selector,

                                    _error: 'rate limit check failed',
                                    _failure: 'yes',
                                    _err_code: err.code
                                };
                                return hookDone(err);
                            }

                            if (!success) {
                                resolution = {
                                    _rate_limit: 'yes',
                                    _selector: selector,
                                    _error: 'too many attempts'
                                };
                                return hookDone(DENYSOFT, DSN.rcpt_too_fast());
                            }

                            plugin.loginfo('RESOLVED rcpt=' + rcpt.address() + ' user=' + userData.address + '[' + userData._id + ']', plugin, connection);

                            // update rate limit for this address after delivery
                            connection.transaction.notes.rateKeys.push({ selector, key, limit: userData.receivedMax });

                            users.set(userData._id.toString(), {
                                userData,
                                recipient: rcpt.address()
                            });

                            resolution = {
                                _user: userData._id.toString(),
                                _resolved: rcpt.address()
                            };
                            return hookDone(OK);
                        });
                    });
                }
            );
        }
    );
};

exports.hook_queue = function(next, connection) {
    let plugin = this;

    const { recipients, forwards, autoreplies, users } = connection.transaction.notes.targets;

    let sendLogEntry = resolution => {
        if (resolution) {
            let messageId = connection.transaction.header.get_all('Message-Id');
            let rspamd = connection.transaction.results.get('rspamd');

            let message = {
                short_message: 'MX SMTP [DATA] ' + connection.transaction.uuid,
                _mail_action: 'data',
                _queue_id: connection.transaction.uuid,
                _message_id: (messageId[0] || '').toString().replace(/^[\s<]+|[\s>]+$/g, ''),
                _spam_score: rspamd ? rspamd.score : '',
                _mail_from: connection.transaction.notes.sender
            };

            Object.keys(resolution).forEach(key => {
                if (resolution[key]) {
                    message[key] = resolution[key];
                }
            });

            plugin.loggelf(message);
        }
    };

    let collector = new StreamCollect();

    let collectData = done => {
        // buffer message chunks by draining the stream
        collector.on('data', () => false); //just drain
        connection.transaction.message_stream.once('error', err => collector.emit('error', err));
        collector.once('end', done);

        collector.once('error', err => {
            plugin.logerror('PIPEFAIL error=' + err.message, plugin, connection);
            sendLogEntry({
                full_message: err.stack,

                _error: 'pipefail processing input',
                _failure: 'yes',
                _err_code: err.code
            });
            return next(DENYSOFT, 'Failed to Queue message');
        });

        connection.transaction.message_stream.pipe(collector);
    };

    let forwardMessage = done => {
        if (!forwards.size) {
            // the message does not need forwarding at this point
            return collectData(done);
        }

        let rspamd = connection.transaction.results.get('rspamd');
        if (rspamd && rspamd.score && plugin.cfg.spamScoreForwarding && rspamd.score >= plugin.cfg.spamScoreForwarding) {
            // do not forward spam messages
            plugin.loginfo('FORWARDSKIP score=' + JSON.stringify(rspamd.score) + ' required=' + plugin.cfg.spamScoreForwarding, plugin, connection);

            sendLogEntry({
                short_message: 'MX SMTP [Skip forward] ' + connection.transaction.uuid,
                _mail_action: 'forward',
                _spam_score: rspamd.score,
                _spam_allowed: plugin.cfg.spamScoreForwarding
            });

            return plugin.db.database.collection('messagelog').insertOne(
                {
                    id: connection.transaction.uuid,
                    queueId: connection.transaction.uuid,
                    action: 'FORWARDSKIP',
                    from: connection.transaction.notes.sender,
                    to: Array.from(recipients),
                    score: rspamd.score,
                    created: new Date()
                },
                () => collectData(done)
            );
        }

        let targets =
            (forwards.size &&
                Array.from(forwards).map(row => ({
                    type: row[1].type,
                    value: row[1].value,
                    recipient: row[1].recipient
                }))) ||
            false;

        let mail = {
            parentId: connection.transaction.notes.id,
            reason: 'forward',

            from: connection.transaction.notes.sender,
            to: [],

            targets,

            interface: 'forwarder'
        };

        let message = plugin.maildrop.push(mail, (err, ...args) => {
            if (err || !args[0]) {
                if (err) {
                    err.code = err.code || 'ERRCOMPOSE';
                    sendLogEntry({
                        full_message: err.stack,

                        _error: 'failed to store message',
                        _failure: 'yes',
                        _err_code: err.code
                    });
                    return next(DENYSOFT, 'Failed to Queue message');
                }
                return done(err, ...args);
            }

            sendLogEntry({
                short_message: 'MX SMTP [Queued forward] ' + connection.transaction.uuid,
                _mail_action: 'forward',
                _target_queue_id: args[0].id,
                _target_address: (targets || []).map(target => ((target && target.value) || target).toString().replace(/\?.*$/, '')).join('\n')
            });

            plugin.loggelf({
                _queue_id: args[0].id,

                short_message: 'MX SMTP [QUEUED] ' + args[0].id,

                _parent_id: connection.transaction.uuid,
                _from: connection.transaction.notes.sender,
                _to: (targets || []).map(target => ((target && target.value) || target).toString().replace(/\?.*$/, '')).join('\n'),

                _queued: 'yes',
                _forwarded: 'yes',

                _interface: 'mx'
            });

            plugin.loginfo('QUEUED FORWARD queue-id=' + args[0].id, plugin, connection);

            plugin.db.database.collection('messagelog').insertOne(
                {
                    id: args[0].id,
                    messageId: args[0].messageId,
                    queueId: connection.transaction.uuid,
                    action: 'FORWARD',
                    from: connection.transaction.notes.sender,
                    to: Array.from(recipients),
                    targets,
                    created: new Date()
                },
                () => done(err, args && args[0] && args[0].id)
            );
        });

        if (message) {
            connection.transaction.message_stream.once('error', err => message.emit('error', err));
            message.once('error', err => {
                plugin.logerror('QUEUEERROR Failed to retrieve message. error=' + err.message, plugin, connection);
                sendLogEntry({
                    full_message: err.stack,

                    _error: 'failed to retrieve message from input',
                    _failure: 'yes',
                    _err_code: err.code
                });
                return next(DENYSOFT, 'Failed to Queue message');
            });

            // pipe the message to the collector object to gather message chunks for further processing
            connection.transaction.message_stream.pipe(collector).pipe(message);
        }
    };

    let sendAutoreplies = done => {
        if (!autoreplies.size) {
            return done();
        }
        // TODO: send autoreply messages

        let curtime = new Date();
        let pos = 0;
        let targets = Array.from(autoreplies);
        let processNext = () => {
            if (pos >= targets.length) {
                return done();
            }

            let target = targets[pos++];
            let addressData = target[1];

            let autoreplyData = addressData.autoreply;
            autoreplyData._id = autoreplyData._id || addressData._id;

            if (!autoreplyData || !autoreplyData.status) {
                return setImmediate(processNext);
            }

            if (autoreplyData.start && autoreplyData.start > curtime) {
                return setImmediate(processNext);
            }

            if (autoreplyData.end && autoreplyData.end < curtime) {
                return setImmediate(processNext);
            }

            autoreply(
                {
                    db: plugin.db,
                    queueId: connection.transaction.uuid,
                    maildrop: plugin.maildrop,
                    sender: connection.transaction.notes.sender,
                    recipient: addressData.address,
                    chunks: collector.chunks,
                    chunklen: collector.chunklen,
                    messageHandler: plugin.db.messageHandler
                },
                autoreplyData,
                (err, ...args) => {
                    if (err || !args[0]) {
                        if (err) {
                            // don't really care
                            plugin.lognotice('AUTOREPLY ERROR target=' + connection.transaction.notes.sender + ' error=' + err.message, plugin, connection);
                            return processNext();
                        }
                        return done(err, ...args);
                    }

                    sendLogEntry({
                        short_message: 'MX SMTP [Queued autoreply] ' + connection.transaction.uuid,
                        _mail_action: 'autoreply',
                        _target_queue_id: args[0].id,
                        _target_address: addressData.address
                    });

                    plugin.loggelf({
                        _queue_id: args[0].id,

                        short_message: 'MX SMTP [QUEUED] ' + args[0].id,

                        _parent_id: connection.transaction.uuid,
                        _from: addressData.address,
                        _to: addressData.address,

                        _queued: 'yes',
                        _autoreply: 'yes',

                        _interface: 'mx'
                    });

                    plugin.loginfo('QUEUED AUTOREPLY target=' + connection.transaction.notes.sender + ' queue-id=' + args[0].id, plugin, connection);
                    return done(err, ...args);
                }
            );
        };
        processNext();
    };

    // update rate limit counters for all recipients
    let updateRateLimits = done => {
        let rateKeys = connection.transaction.notes.rateKeys || [];
        let pos = 0;
        let processKey = () => {
            if (pos >= rateKeys.length) {
                plugin.logdebug('Rate keys processed', plugin, connection);
                return done();
            }

            let rateKey = rateKeys[pos++];
            plugin.logdebug('Rate key. key=' + JSON.stringify(rateKey), plugin, connection);
            plugin.updateRateLimit(connection, rateKey.selector || 'rcpt', rateKey.key, rateKey.limit, processKey);
        };
        processKey();
    };

    let logEntry = done => {
        let rspamd = connection.transaction.results.get('rspamd');
        return plugin.db.database.collection('messagelog').insertOne(
            {
                id: connection.transaction.uuid,
                queueId: connection.transaction.uuid,
                action: 'MX',
                from: connection.transaction.notes.sender,
                to: Array.from(recipients),
                score: rspamd && rspamd.score,
                created: new Date()
            },
            done
        );
    };

    logEntry(() => {
        // try to forward the message. If forwarding is not needed then continues immediatelly
        forwardMessage(() => {
            // send autoreplies to forwarded addresses (if needed)
            sendAutoreplies(() => {
                let prepared = false;

                let userList = Array.from(users).map(e => e[1]);
                let stored = 0;

                let storeNext = () => {
                    if (stored >= userList.length) {
                        return updateRateLimits(() => next(OK, 'Message processed'));
                    }

                    let rcptData = userList[stored++];
                    let recipient = rcptData.recipient;
                    let userData = rcptData.userData;

                    plugin.logdebug(plugin, 'Filtering message for ' + recipient, plugin, connection);
                    plugin.filterHandler.process(
                        {
                            mimeTree: prepared && prepared.mimeTree,
                            maildata: prepared && prepared.maildata,
                            user: userData,
                            sender: connection.transaction.notes.sender,
                            recipient,
                            chunks: collector.chunks,
                            chunklen: collector.chunklen,
                            meta: {
                                transactionId: connection.transaction.uuid,
                                source: 'MX',
                                from: connection.transaction.notes.sender,
                                to: [recipient],
                                origin: connection.remote_ip,
                                transhost: connection.hello.host,
                                transtype: connection.transaction.notes.transmissionType,
                                time: new Date()
                            }
                        },
                        (err, response, preparedResponse) => {
                            if (err) {
                                plugin.db.database.collection('messagelog').insertOne(
                                    {
                                        id: connection.transaction.uuid,
                                        queueId: connection.transaction.uuid,
                                        action: 'ERROR',
                                        error: err.message,
                                        created: new Date()
                                    },
                                    () => false
                                );

                                sendLogEntry({
                                    full_message: err.stack,

                                    _user: userData._id.toString(),
                                    _address: recipient,

                                    _no_store: 'yes',
                                    _error: 'failed to store message',
                                    _failure: 'yes',
                                    _err_code: err.code
                                });

                                // we can fail the message even if some recipients were already processed
                                // as redelivery would not be a problem - duplicate deliveries are ignored (filters are rerun though).
                                plugin.loginfo('DEFERRED rcpt=' + recipient + ' error=' + err.message, plugin, connection);
                                return next(DENYSOFT, 'Failed to Queue message');
                            }

                            let isSpam = false;
                            let filterMessages = [];
                            if (response && response.filterResults && response.filterResults.length) {
                                response.filterResults.forEach(entry => {
                                    if (entry.forward) {
                                        sendLogEntry({
                                            short_message: 'MX SMTP [Queued forward] ' + connection.transaction.uuid,
                                            _user: userData._id.toString(),
                                            _address: recipient,
                                            _mail_action: 'forward',
                                            _target_queue_id: entry['forward-queue-id'],
                                            _target_address: entry.forward
                                        });

                                        plugin.loggelf({
                                            _queue_id: entry['forward-queue-id'],

                                            short_message: 'MX SMTP [QUEUED] ' + entry['forward-queue-id'],

                                            _parent_id: connection.transaction.uuid,
                                            _from: recipient,
                                            _to: entry.forward,

                                            _queued: 'yes',
                                            _forwarded: 'yes',

                                            _interface: 'mx'
                                        });
                                        return;
                                    }

                                    if (entry.autoreply) {
                                        sendLogEntry({
                                            short_message: 'MX SMTP [Queued autoreply] ' + connection.transaction.uuid,
                                            _mail_action: 'autoreply',
                                            _user: userData._id.toString(),
                                            _address: recipient,
                                            _target_queue_id: entry['autoreply-queue-id'],
                                            _target_address: entry.autoreply
                                        });

                                        plugin.loggelf({
                                            _queue_id: entry['autoreply-queue-id'],

                                            short_message: 'MX SMTP [QUEUED] ' + entry['autoreply-queue-id'],

                                            _parent_id: connection.transaction.uuid,
                                            _from: recipient,
                                            _to: entry.autoreply,

                                            _queued: 'yes',
                                            _autoreply: 'yes',

                                            _interface: 'mx'
                                        });
                                        return;
                                    }

                                    if (entry.spam) {
                                        isSpam = true;
                                        return;
                                    }

                                    Object.keys(entry).forEach(key => {
                                        if (!entry[key]) {
                                            return;
                                        }
                                        if (typeof entry[key] === 'boolean') {
                                            filterMessages.push(key);
                                        } else {
                                            filterMessages.push(key + '=' + (entry[key] || '').toString());
                                        }
                                    });
                                });
                                if (filterMessages.length) {
                                    plugin.loginfo('FILTER ACTIONS ' + filterMessages.join(','), plugin, connection);
                                }
                            }

                            if (response && response.error) {
                                if (response.error.code === 'DroppedByPolicy') {
                                    sendLogEntry({
                                        full_message: response.error.message,

                                        _user: userData._id.toString(),
                                        _address: recipient,
                                        _filter: filterMessages.length ? filterMessages.join('\n') : false,
                                        _is_spam: isSpam ? 'yes' : 'no',

                                        _no_store: 'yes',
                                        _error: 'message dropped',
                                        _dropped: 'yes',
                                        _err_code: response.error.code
                                    });
                                    plugin.loginfo(
                                        'DROPPED rcpt=' + recipient + ' user=' + userData.address + '[' + userData._id + '] error=' + response.error.message,
                                        plugin,
                                        connection
                                    );
                                } else {
                                    sendLogEntry({
                                        full_message: response.error.stack,

                                        _user: userData._id.toString(),
                                        _address: recipient,
                                        _filter: filterMessages.length ? filterMessages.join('\n') : false,
                                        _is_spam: isSpam ? 'yes' : 'no',

                                        _no_store: 'yes',
                                        _error: 'failed to store message',
                                        _failure: 'yes',
                                        _err_code: response.error.code
                                    });
                                    plugin.loginfo(
                                        'DEFERRED rcpt=' + recipient + ' user=' + userData.address + '[' + userData._id + '] error=' + response.error.message,
                                        plugin,
                                        connection
                                    );
                                }

                                return next(response.error.code === 'DroppedByPolicy' ? DENY : DENYSOFT, response.error.message);
                            }

                            sendLogEntry({
                                _user: userData._id.toString(),
                                _address: recipient,
                                _stored: 'yes',
                                _result: response.response,
                                _filter: filterMessages.length ? filterMessages.join('\n') : false,
                                _is_spam: isSpam ? 'yes' : 'no'
                            });

                            plugin.loginfo(
                                'STORED rcpt=' + recipient + ' user=' + userData.address + '[' + userData._id + '] result=' + response.response,
                                plugin,
                                connection
                            );

                            if (!prepared && preparedResponse) {
                                // reuse parsed message structure
                                prepared = preparedResponse;
                            }

                            setImmediate(storeNext);
                        }
                    );
                };
                storeNext();
            });
        });
    });
};

// Rate limit is checked on RCPT TO
exports.checkRateLimit = function(connection, selector, key, limit, next) {
    let plugin = this;

    limit = Number(limit) || plugin.cfg.limits[selector];
    if (!limit) {
        return next(null, true);
    }

    let windowSize = plugin.cfg.limits[selector + 'WindowSize'] || plugin.cfg.limits.windowSize || 1 * 3600;

    plugin.ttlcounter('rl:' + selector + ':' + key, 0, limit, windowSize, (err, result) => {
        if (err) {
            plugin.logerror('RATELIMITERR error=' + err.message, plugin, connection);
            return next(err);
        }

        if (!result.success) {
            connection.lognotice(
                'RATELIMITED key=' + key + ' selector=' + selector + ' limit=' + limit + ' value=' + result.value + ' ttl=' + result.ttl,
                plugin,
                connection
            );
        }

        return next(null, result.success);
    });
};

// Update rate limit counters on successful delivery
exports.updateRateLimit = function(connection, selector, key, limit, next) {
    let plugin = this;

    limit = Number(limit) || plugin.cfg.limits[selector];
    if (!limit) {
        return next(null, true);
    }

    let windowSize = plugin.cfg.limits[selector + 'WindowSize'] || plugin.cfg.limits.windowSize || 1 * 3600;

    plugin.ttlcounter('rl:' + selector + ':' + key, 1, limit, windowSize, (err, result) => {
        if (err) {
            plugin.logerror('RATELIMITERR error=' + err.message, plugin, connection);
            return next(err);
        }

        connection.logdebug(
            'Rate limit key=' + key + ' selector=' + selector + ' limit=' + limit + ' value=' + result.value + ' ttl=' + result.ttl,
            plugin,
            connection
        );

        return next(null, result.success);
    });
};
