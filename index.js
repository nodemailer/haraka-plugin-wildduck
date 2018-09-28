/* eslint-env es6 */
/* globals DENY: false, OK: false, DENYSOFT: false */

'use strict';

// disable config loading by Wild Duck
process.env.DISABLE_WILD_CONFIG = 'true';

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
                spamScoreValue: plugin.cfg.spamScore
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
    let from = params[0];
    connection.transaction.notes.sender = from.address();

    connection.transaction.notes.id = new ObjectID();
    connection.transaction.notes.rateKeys = [];
    connection.transaction.notes.targets = {
        users: new Map(),
        forward: new Map(),
        recipients: new Set(),
        autoreplies: new Map()
    };

    connection.transaction.notes.transmissionType = []
        .concat(connection.greeting === 'EHLO' ? 'E' : [])
        .concat('SMTP')
        .concat(connection.tls_cipher ? 'S' : [])
        .join('');

    return next();
};

exports.hook_rcpt = function(next, connection, params) {
    let plugin = this;

    let rcpt = params[0];
    if (/\*/.test(rcpt.user)) {
        // Using * is not allowed in addresses
        return next(DENY, DSN.no_such_user());
    }

    let address = plugin.normalize_address(rcpt);

    connection.transaction.notes.targets.recipients.add(address);

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
                return next(DENY, DSN.no_such_user());
            }

            reversed = reversed.join('@');
        } catch (E) {
            plugin.logerror('SRS FAILED rcpt=' + address + ' error=' + E.message, plugin, connection);
            return next(DENY, DSN.no_such_user());
        }

        if (reversed) {
            // accept SRS rewritten address
            let key = reversed;
            let selector = 'rcpt';
            return plugin.checkRateLimit(connection, selector, key, false, (err, success) => {
                if (err) {
                    return next(err);
                }

                if (!success) {
                    return next(DENYSOFT, DSN.rcpt_too_fast());
                }

                // update rate limit for this address after delivery
                connection.transaction.notes.rateKeys.push({ selector, key });

                plugin.loginfo('SRS USING rcpt=' + address + ' target=' + reversed, plugin, connection);

                connection.transaction.notes.targets.forward.set(reversed, { type: 'mail', value: reversed });
                return next(OK);
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
                    return next(err);
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
                    return next(DENYSOFT, DSN.rcpt_too_fast());
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
                    connection.transaction.notes.targets.autoreplies.set(addressData.addrview, addressData);
                }

                let pos = 0;
                let processTarget = () => {
                    if (pos >= addressData.targets.length) {
                        return next(OK);
                    }

                    let target = addressData.targets[pos++];

                    if (target.type === 'relay') {
                        // relay is not rate limited
                        target.recipient = rcpt.address();
                        connection.transaction.notes.targets.forward.set(target.value, target);
                        return setImmediate(processTarget);
                    }

                    if (target.type === 'http' || (target.type === 'mail' && !target.user)) {
                        if (target.type !== 'mail') {
                            target.recipient = rcpt.address();
                        }

                        connection.transaction.notes.targets.forward.set(target.value, target);
                        return setImmediate(processTarget);
                    }

                    if (target.type !== 'mail') {
                        // no idea what to do here, some new feature probably
                        return setImmediate(processTarget);
                    }

                    if (connection.transaction.notes.targets.users.has(target.user.toString())) {
                        return setImmediate(processTarget);
                    }

                    // we have a target user, so we need to resolve user data
                    plugin.db.users.collection('users').findOne(
                        { _id: target.user },
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
                                return next(err);
                            }

                            if (!userData || userData.disabled) {
                                return setImmediate(processTarget);
                            }

                            // max quota for the user
                            let quota = userData.quota || consts.MAX_STORAGE;

                            if (userData.storageUsed && quota <= userData.storageUsed) {
                                // can not deliver mail to this user, over quota
                                return setImmediate(processTarget);
                            }

                            connection.transaction.notes.targets.users.set(userData._id.toString(), { user: userData, recipient: rcpt.address() });
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
        { wildcard: true, projection: { name: true, address: true, addrview: true, autoreply: true } },
        (err, addressData) => {
            if (err) {
                return next(err);
            }

            if (addressData && addressData.targets) {
                return handleForwardingAddress(addressData);
            }

            if (!addressData || !addressData.user) {
                plugin.logdebug('No such user ' + address, plugin, connection);
                return next(DENY, DSN.no_such_user());
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
                        return next(err);
                    }

                    if (!userData) {
                        return next(DENY, DSN.no_such_user());
                    }

                    if (userData.disabled) {
                        // user is disabled for whatever reason
                        return next(DENY, DSN.mbox_disabled());
                    }

                    // max quota for the user
                    let quota = userData.quota || consts.MAX_STORAGE;

                    if (userData.storageUsed && quota <= userData.storageUsed) {
                        // can not deliver mail to this user, over quota
                        return next(DENY, DSN.mbox_full());
                    }

                    let checkIpRateLimit = done => {
                        if (!connection.remote.ip) {
                            return done();
                        }

                        let key = connection.remote.ip + ':' + userData._id.toString();
                        let selector = 'rcptIp';
                        plugin.checkRateLimit(connection, selector, key, false, (err, success) => {
                            if (err) {
                                return next(err);
                            }

                            if (!success) {
                                return next(DENYSOFT, DSN.rcpt_too_fast());
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
                                return next(err);
                            }

                            if (!success) {
                                return next(DENYSOFT, DSN.rcpt_too_fast());
                            }

                            plugin.loginfo('RESOLVED rcpt=' + rcpt.address() + ' user=' + userData.address + '[' + userData._id + ']', plugin, connection);

                            // update rate limit for this address after delivery
                            connection.transaction.notes.rateKeys.push({ selector, key, limit: userData.receivedMax });

                            connection.transaction.notes.targets.users.set(userData._id.toString(), { user: userData, recipient: rcpt.address() });
                            return next(OK);
                        });
                    });
                }
            );
        }
    );
};

exports.hook_queue = function(next, connection) {
    let plugin = this;

    let collector = new StreamCollect();

    let collectData = done => {
        // buffer message chunks by draining the stream
        collector.on('data', () => false); //just drain
        connection.transaction.message_stream.once('error', err => collector.emit('error', err));
        collector.once('end', done);

        collector.once('error', err => {
            plugin.logerror('PIPEFAIL error=' + err.message, plugin, connection);
            return next(DENYSOFT, 'Failed to Queue message');
        });

        connection.transaction.message_stream.pipe(collector);
    };

    let forwardMessage = done => {
        if (!connection.transaction.notes.targets.forward.size) {
            // the message does not need forwarding at this point
            return collectData(done);
        }

        let rspamd = connection.transaction.results.get('rspamd');
        if (rspamd && rspamd.score && plugin.cfg.spamScoreForwarding && rspamd.score >= plugin.cfg.spamScoreForwarding) {
            // do not forward spam messages
            plugin.loginfo('FORWARDSKIP score=' + JSON.stringify(rspamd.score) + ' required=' + plugin.cfg.spamScoreForwarding, plugin, connection);

            return plugin.db.database.collection('messagelog').insertOne(
                {
                    id: connection.transaction.uuid,
                    queueId: connection.transaction.uuid,
                    action: 'FORWARDSKIP',
                    from: connection.transaction.notes.sender,
                    to: Array.from(connection.transaction.notes.targets.recipients),
                    score: rspamd.score,
                    created: new Date()
                },
                () => collectData(done)
            );
        }

        let targets =
            (connection.transaction.notes.targets.forward.size &&
                Array.from(connection.transaction.notes.targets.forward).map(row => ({
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
                    return next(DENYSOFT, 'Failed to Queue message');
                }
                return done(err, ...args);
            }

            plugin.loginfo('QUEUED FORWARD queue-id=' + args[0].id, plugin, connection);

            plugin.db.database.collection('messagelog').insertOne(
                {
                    id: args[0].id,
                    messageId: args[0].messageId,
                    queueId: connection.transaction.uuid,
                    action: 'FORWARD',
                    from: connection.transaction.notes.sender,
                    to: Array.from(connection.transaction.notes.targets.recipients),
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
                return next(DENYSOFT, 'Failed to Queue message');
            });

            // pipe the message to the collector object to gather message chunks for further processing
            connection.transaction.message_stream.pipe(collector).pipe(message);
        }
    };

    let sendAutoreplies = done => {
        if (!connection.transaction.notes.targets.autoreplies.size) {
            return done();
        }
        // TODO: send autoreply messages

        let curtime = new Date();
        let pos = 0;
        let targets = Array.from(connection.transaction.notes.targets.autoreplies);
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
                to: Array.from(connection.transaction.notes.targets.recipients),
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

                let users = Array.from(connection.transaction.notes.targets.users).map(e => e[1]);
                let stored = 0;

                let storeNext = () => {
                    if (stored >= users.length) {
                        return updateRateLimits(() => next(OK, 'Message processed'));
                    }

                    let rcptData = users[stored++];
                    let recipient = rcptData.recipient;
                    let userData = rcptData.user;

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
                                // we can fail the message even if some recipients were already processed
                                // as redelivery would not be a problem - duplicate deliveries are ignored (filters are rerun though).
                                plugin.loginfo('DEFERRED rcpt=' + recipient + ' error=' + err.message, plugin, connection);
                                return next(DENYSOFT, 'Failed to Queue message');
                            }

                            if (response && response.filterResults && response.filterResults.length) {
                                let msg = [];
                                response.filterResults.forEach(entry => {
                                    Object.keys(entry).forEach(key => {
                                        if (!entry[key]) {
                                            return;
                                        }
                                        if (typeof entry[key] === 'boolean') {
                                            msg.push(key);
                                        } else {
                                            msg.push(key + '=' + (entry[key] || '').toString());
                                        }
                                    });
                                });
                                if (msg.length) {
                                    plugin.loginfo('FILTER ACTIONS ' + msg.join(' '), plugin, connection);
                                }
                            }

                            if (response && response.error) {
                                if (response.error.code === 'DroppedByPolicy') {
                                    plugin.loginfo(
                                        'DROPPED rcpt=' + recipient + ' user=' + userData.address + '[' + userData._id + '] error=' + response.error.message,
                                        plugin,
                                        connection
                                    );
                                } else {
                                    plugin.loginfo(
                                        'DEFERRED rcpt=' + recipient + ' user=' + userData.address + '[' + userData._id + '] error=' + response.error.message,
                                        plugin,
                                        connection
                                    );
                                }

                                return next(response.error.code === 'DroppedByPolicy' ? DENY : DENYSOFT, response.error.message);
                            }

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
