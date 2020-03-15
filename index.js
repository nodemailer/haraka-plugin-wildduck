/* eslint-env es6 */
/* globals DENY: false, OK: false, DENYSOFT: false */

'use strict';

// disable config loading by Wild Duck
process.env.DISABLE_WILD_CONFIG = 'true';

const os = require('os');
const ObjectID = require('mongodb').ObjectID;
const db = require('./lib/db');
const DSN = require('haraka-dsn');
const punycode = require('punycode');
const SRS = require('srs.js');
const counters = require('wildduck/lib/counters');
const tools = require('wildduck/lib/tools');
const StreamCollect = require('./lib/stream-collect');
const Maildropper = require('wildduck/lib/maildropper');
const FilterHandler = require('wildduck/lib/filter-handler');
const autoreply = require('wildduck/lib/autoreply');
const consts = require('wildduck/lib/consts');
const wdErrors = require('wildduck/lib/errors');
const Gelf = require('gelf');
const addressparser = require('nodemailer/lib/addressparser');
const libmime = require('libmime');

DSN.rcpt_too_fast = () =>
    DSN.create(
        450,
        'The user you are trying to contact is receiving mail at a rate that\nprevents additional messages from being delivered. Please resend your\nmessage at a later time. If the user is able to receive mail at that\ntime, your message will be delivered.',
        2,
        1
    );

let defaultSpamRejectMessage =
    'Our system has detected that this message is likely unsolicited mail.\nTo reduce the amount of spam this message has been blocked.';

exports.register = function() {
    const plugin = this;
    plugin.logdebug('Initializing rcpt_to Wild Duck plugin.', plugin);
    plugin.load_wildduck_ini();

    plugin.register_hook('init_master', 'init_wildduck_shared');
    plugin.register_hook('init_child', 'init_wildduck_shared');
};

exports.load_wildduck_ini = function() {
    const plugin = this;

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
    const plugin = this;

    plugin.srsRewriter = new SRS({
        secret: (plugin.cfg.srs && plugin.cfg.srs.secret) || 'secret'
    });

    plugin.rspamd = plugin.cfg.rspamd || {};
    plugin.rspamd.forwardSkip = Number(plugin.rspamd.forwardSkip) || Number(plugin.cfg.spamScoreForwarding) || 0;
    plugin.rspamd.blacklist = [].concat(plugin.rspamd.blacklist || []);
    plugin.rspamd.softlist = [].concat(plugin.rspamd.softlist || []);
    plugin.rspamd.responses = plugin.rspamd.responses || {};

    plugin.hostname = (plugin.cfg.gelf && plugin.cfg.gelf.hostname) || os.hostname();
    plugin.gelf =
        plugin.cfg.gelf && plugin.cfg.gelf.enabled
            ? new Gelf(plugin.cfg.gelf.options)
            : {
                  // placeholder
                  emit: (level, message) => {
                      plugin.loginfo('GELF ' + JSON.stringify(message), plugin);
                  }
              };
    wdErrors.setGelf(plugin.gelf);

    plugin.loggelf = message => {
        if (typeof message === 'string') {
            message = {
                short_message: message
            };
        }
        message = message || {};

        const component = (plugin.cfg.gelf && plugin.cfg.gelf.component) || 'mx';
        if (!message.short_message || message.short_message.indexOf(component.toUpperCase()) !== 0) {
            message.short_message = component.toUpperCase() + ' ' + (message.short_message || '');
        }

        message.facility = component; // facility is deprecated but set by the driver if not provided
        message.host = plugin.hostname;
        message.timestamp = Date.now() / 1000;
        message._component = component;

        Object.keys(message).forEach(key => {
            if (!message[key]) {
                delete message[key];
            }
        });
        plugin.gelf.emit('gelf.log', message);
    };

    let createConnection = done => {
        db.connect(server.notes.redis, plugin.cfg, (err, db) => {
            if (err) {
                return done(err);
            }
            plugin.db = db;
            plugin.ttlcounter = counters(db.redis).ttlcounter;

            plugin.db.messageHandler.loggelf = message => plugin.loggelf(message);
            plugin.db.userHandler.loggelf = message => plugin.loggelf(message);

            plugin.maildrop = new Maildropper({
                db,
                enabled: plugin.cfg.sender.enabled,
                zone: plugin.cfg.sender.zone,
                collection: plugin.cfg.sender.collection,
                gfs: plugin.cfg.sender.gfs
            });

            plugin.filterHandler = new FilterHandler({
                db,
                sender: plugin.cfg.sender,
                messageHandler: plugin.db.messageHandler,
                loggelf: message => plugin.loggelf(message)
            });

            done();
        });
    };

    let returned = false;
    let tryCreateConnection = () => {
        createConnection(err => {
            if (err) {
                if (!returned) {
                    plugin.logcrit('Database connection failed. ' + err.message, plugin);
                    returned = true;
                    next();
                }
                // keep trying to open up the DB connection
                setTimeout(tryCreateConnection, 2 * 1000);
                return;
            }

            plugin.loginfo('Database connection opened', plugin);
            if (!returned) {
                returned = true;
                next();
            }
        });
    };

    tryCreateConnection();
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
    const plugin = this;

    plugin.open_database(server, next);
};

exports.hook_deny = function(next, connection, params) {
    const plugin = this;
    const tnx = connection.transaction;
    let remoteIp = connection.remote_ip;

    if (tnx === null) {
        next();
        return;
    }

    let rcpts = tnx.rcpt_to || [];
    if (!rcpts.length) {
        rcpts = [false];
    }

    for (let rcpt of rcpts) {
        let user;
        let address = (rcpt && rcpt.address()) || false;

        if (tnx.notes.targets && tnx.notes.targets.users) {
            // try to resolve user id for the recipient address
            for (let target of tnx.notes.targets.users) {
                let uid = target[0];
                let info = target[1];
                if (info && info.recipient === address) {
                    user = uid;
                }
            }
        }

        let logdata = {
            short_message: '[DENY:' + tnx.notes.sender + '] ' + tnx.uuid,
            _mail_action: 'deny',
            _from: tnx.notes.sender,
            _queue_id: tnx.uuid,
            _ip: remoteIp,
            _proto: tnx.notes.transmissionType,
            _to: address,
            _user: user,
            _rejector: params && params[2],
            _reject_code: tnx.notes.rejectCode || (params && params[2]) || 'UNKNOWN'
        };

        let headerFrom = plugin.getHeaderFrom(tnx);
        if (headerFrom) {
            logdata._header_from_address = headerFrom.address;
            logdata._header_from_value = tnx.header.get_all('From').join('; ');
        }

        let err = params && params[1];
        if (typeof err === 'string') {
            logdata._error = err;
        } else if (err && typeof err === 'object') {
            Object.keys(err).forEach(key => {
                if (key === 'msg') {
                    logdata._error = err[key];
                } else {
                    logdata['_error_' + key] = err[key];
                }
            });
        }

        plugin.loggelf(logdata);
    }

    next();
};

exports.hook_mail = function(next, connection, params) {
    const plugin = this;
    const tnx = connection.transaction;

    let from = params[0];
    tnx.notes.sender = from.address();

    tnx.notes.id = new ObjectID();
    tnx.notes.rateKeys = [];
    tnx.notes.targets = {
        users: new Map(),
        forwards: new Map(),
        recipients: new Set(),
        autoreplies: new Map()
    };

    tnx.notes.transmissionType = []
        .concat(connection.greeting === 'EHLO' ? 'E' : [])
        .concat('SMTP')
        .concat(connection.tls_cipher ? 'S' : [])
        .join('');

    plugin.loggelf({
        short_message: '[MAIL FROM:' + tnx.notes.sender + '] ' + tnx.uuid,

        _mail_action: 'mail_from',
        _from: tnx.notes.sender,
        _queue_id: tnx.uuid,
        _ip: connection.remote_ip,
        _proto: tnx.notes.transmissionType
    });

    return next();
};

exports.hook_rcpt = function(next, connection, params) {
    const plugin = this;
    const tnx = connection.transaction;

    let tryCount = 0;
    let tryTimer = false;
    let returned = false;
    let waitTimeout = false;

    let runHandler = () => {
        clearTimeout(tryTimer);
        plugin.real_rcpt_handler(
            (...args) => {
                clearTimeout(waitTimeout);
                if (returned) {
                    return;
                }
                returned = true;
                let err = args && args[0];
                if (err && /Error$/.test(err.name)) {
                    plugin.logerror(err, plugin, connection);
                    tnx.notes.rejectCode = 'ERRC01';
                    return next(DENYSOFT, 'Failed to process recipient, try again [ERRC01]');
                }
                next(...args);
            },
            connection,
            params
        );
    };

    // rcpt check requires access to the db which might not be available yet
    let runCheck = () => {
        if (returned) {
            return;
        }
        if (!plugin.db) {
            // database not opened yet
            if (tryCount++ < 5) {
                tryTimer = setTimeout(runCheck, tryCount * 150);
                return;
            }
            clearTimeout(waitTimeout);
            returned = true;
            tnx.notes.rejectCode = 'ERRC02';
            return next(DENYSOFT, 'Failed to process recipient, try again [ERRC02]');
        }
        runHandler();
    };

    waitTimeout = setTimeout(() => {
        clearTimeout(waitTimeout);
        if (returned) {
            return;
        }
        returned = true;
        tnx.notes.rejectCode = 'ERRC03';
        return next(DENYSOFT, 'Failed to process recipient, try again [ERRC03]');
    }, 8 * 1000);

    runCheck();
};

exports.real_rcpt_handler = function(next, connection, params) {
    const plugin = this;
    const tnx = connection.transaction;
    const remoteIp = connection.remote_ip;

    const { recipients, forwards, autoreplies, users } = tnx.notes.targets;

    let rcpt = params[0];
    if (/\*/.test(rcpt.user)) {
        // Using * is not allowed in addresses
        tnx.notes.rejectCode = 'NO_SUCH_USER';
        return next(DENY, DSN.no_such_user());
    }

    let address = plugin.normalize_address(rcpt);

    recipients.add(address);

    let resolution = false;
    let hookDone = (...args) => {
        if (resolution) {
            let message = {
                short_message: '[RCPT TO:' + rcpt.address() + '] ' + tnx.uuid,
                _mail_action: 'rcpt_to',
                _from: tnx.notes.sender,
                _to: rcpt.address(),
                _queue_id: tnx.uuid,
                _ip: remoteIp,
                _proto: tnx.notes.transmissionType
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
                tnx.notes.rejectCode = 'NO_SUCH_USER';
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
            tnx.notes.rejectCode = 'NO_SUCH_USER';
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
                    err.code = err.code || 'RateLimit';
                    return hookDone(err);
                }

                if (!success) {
                    resolution = {
                        _srs: 'yes',
                        _rate_limit: 'yes',
                        _selector: selector,
                        _error: 'too many attempts'
                    };
                    tnx.notes.rejectCode = 'RATE_LIMIT';
                    return hookDone(DENYSOFT, DSN.rcpt_too_fast());
                }

                // update rate limit for this address after delivery
                tnx.notes.rateKeys.push({ selector, key });

                plugin.loginfo('SRS USING rcpt=' + address + ' target=' + reversed, plugin, connection);

                forwards.set(reversed, { type: 'mail', value: reversed, recipient: rcpt.address() });

                resolution = {
                    _srs: 'yes',
                    _rcpt_accepted: 'yes',
                    _forward_to: reversed
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
                    err.code = err.code || 'RateLimit';
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
                    tnx.notes.rejectCode = 'RATE_LIMIT';
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
                            _rcpt_accepted: 'yes',
                            _forward_to: forwardTargets.join('\n') || 'empty_list'
                        };
                        return hookDone(OK);
                    }

                    let targetData = addressData.targets[pos++];

                    if (targetData.type === 'relay') {
                        // relay is not rate limited
                        targetData.recipient = addressData.address || rcpt.address();

                        // Do not use `targetData.value` alone as it might be the same for multiple recipients
                        forwards.set(`${targetData.recipient}:${targetData.value}`, targetData);

                        forwardTargets.push(targetData.recipient + ':' + (targetData.value || '').toString().replace(/\?.*$/, ''));
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
                                forwardTargets.push(targetData.value);
                                return setImmediate(processTarget);
                            }

                            if (userData.disabled) {
                                // disabled user, skip
                                forwardTargets.push(targetData.value + ':' + userData._id + '[disabled]');
                                return setImmediate(processTarget);
                            }

                            // max quota for the user
                            let quota = userData.quota || consts.MAX_STORAGE;
                            if (userData.storageUsed && quota <= userData.storageUsed) {
                                // can not deliver mail to this user, over quota, skip
                                forwardTargets.push(targetData.value + ':' + userData._id + '[over_quota]');
                                return setImmediate(processTarget);
                            }

                            users.set(userData._id.toString(), {
                                userData,
                                recipient: rcpt.address()
                            });

                            forwardTargets.push(targetData.value + ':' + userData._id);

                            setImmediate(processTarget);
                        }
                    );
                };

                setImmediate(processTarget);
            }
        );
    };

    let checkIpRateLimit = (userData, done) => {
        if (!remoteIp) {
            return done();
        }

        let key = remoteIp + ':' + userData._id.toString();
        let selector = 'rcptIp';
        plugin.checkRateLimit(connection, selector, key, false, (err, success) => {
            if (err) {
                resolution = {
                    full_message: err.stack,
                    _rate_limit: 'yes',
                    _selector: selector,
                    _user: userData._id.toString(),
                    _default_address: rcpt.address() !== userData.address ? userData.address : '',

                    _error: 'rate limit check failed',
                    _failure: 'yes',
                    _err_code: err.code
                };
                err.code = err.code || 'RateLimit';
                return hookDone(err);
            }

            if (!success) {
                resolution = {
                    _rate_limit: 'yes',
                    _selector: selector,
                    _error: 'too many attempts',
                    _user: userData._id.toString(),
                    _default_address: rcpt.address() !== userData.address ? userData.address : ''
                };
                tnx.notes.rejectCode = 'RATE_LIMIT';
                return hookDone(DENYSOFT, DSN.rcpt_too_fast());
            }

            // update rate limit for this address after delivery
            tnx.notes.rateKeys.push({ selector, key });

            return done();
        });
    };

    plugin.db.userHandler.resolveAddress(
        address,
        {
            wildcard: true,
            projection: {
                name: true,
                address: true,
                addrview: true,
                forwards: true,
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
                err.code = err.code || 'ResolveAddress';
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
                tnx.notes.rejectCode = 'NO_SUCH_USER';
                return hookDone(DENY, DSN.no_such_user());
            }

            plugin.db.userHandler.get(
                addressData.user,
                {
                    // extra fields are needed later in the filtering step
                    name: true,
                    address: true,
                    forwards: true,
                    receivedMax: true,
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
                        err.code = err.code || 'GetUserData';
                        return hookDone(err);
                    }

                    if (!userData) {
                        resolution = {
                            _error: 'no such user',
                            _unknwon_user: 'yes'
                        };
                        tnx.notes.rejectCode = 'NO_SUCH_USER';
                        return hookDone(DENY, DSN.no_such_user());
                    }

                    if (userData.disabled) {
                        // user is disabled for whatever reason
                        resolution = {
                            _user: userData._id.toString(),
                            _error: 'disabled user',
                            _disabled_user: 'yes'
                        };
                        tnx.notes.rejectCode = 'MBOX_DISABLED';
                        return hookDone(DENY, DSN.mbox_disabled());
                    }

                    // max quota for the user
                    let quota = userData.quota || consts.MAX_STORAGE;

                    if (userData.storageUsed && quota <= userData.storageUsed) {
                        // can not deliver mail to this user, over quota
                        resolution = {
                            _user: userData._id.toString(),
                            _error: 'user over quota',
                            _over_quota: 'yes',
                            _default_address: rcpt.address() !== userData.address ? userData.address : ''
                        };
                        tnx.notes.rejectCode = 'MBOX_FULL';
                        return hookDone(DENY, DSN.mbox_full());
                    }

                    checkIpRateLimit(userData, () => {
                        let key = userData._id.toString();
                        let selector = 'rcpt';
                        plugin.checkRateLimit(connection, selector, key, userData.receivedMax, (err, success) => {
                            if (err) {
                                resolution = {
                                    full_message: err.stack,
                                    _rate_limit: 'yes',
                                    _selector: selector,
                                    _user: userData._id.toString(),
                                    _default_address: rcpt.address() !== userData.address ? userData.address : '',

                                    _error: 'rate limit check failed',
                                    _failure: 'yes',
                                    _err_code: err.code
                                };
                                err.code = err.code || 'RateLimit';
                                return hookDone(err);
                            }

                            if (!success) {
                                resolution = {
                                    _rate_limit: 'yes',
                                    _selector: selector,
                                    _error: 'too many attempts',
                                    _user: userData._id.toString(),
                                    _default_address: rcpt.address() !== userData.address ? userData.address : ''
                                };
                                tnx.notes.rejectCode = 'RATE_LIMIT';
                                return hookDone(DENYSOFT, DSN.rcpt_too_fast());
                            }

                            plugin.loginfo('RESOLVED rcpt=' + rcpt.address() + ' user=' + userData.address + '[' + userData._id + ']', plugin, connection);

                            // update rate limit for this address after delivery
                            tnx.notes.rateKeys.push({ selector, key, limit: userData.receivedMax });

                            users.set(userData._id.toString(), {
                                userData,
                                recipient: rcpt.address()
                            });

                            resolution = {
                                _user: userData._id.toString(),
                                _rcpt_accepted: 'yes',
                                _default_address: rcpt.address() !== userData.address ? userData.address : ''
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
    const plugin = this;
    const tnx = connection.transaction;
    const queueId = tnx.uuid;
    const remoteIp = connection.remote_ip;

    const transhost = connection.hello.host;

    let blacklisted = this.checkRspamdBlacklist(tnx);
    if (blacklisted) {
        // can not send DSN object for hook_queue as it is converted to [object Object]
        tnx.notes.rejectCode = blacklisted.key;
        return next(DENY, plugin.dsnSpamResponse(tnx, blacklisted.key).reply);
    }

    let softlisted = this.checkRspamdSoftlist(tnx);
    if (softlisted) {
        // can not send DSN object for hook_queue as it is converted to [object Object]
        tnx.notes.rejectCode = softlisted.key;
        return next(DENYSOFT, plugin.dsnSpamResponse(tnx, softlisted.key).reply);
    }

    // results about verification (TLS, SPF, DKIM)
    let verificationResults = {
        tls: false,
        spf: false,
        dkim: false
    };

    let tlsResults = connection.results.get('tls');
    if (tlsResults && tlsResults.enabled) {
        verificationResults.tls = tlsResults.cipher;
    }

    // find domain that sent this message (SPF Pass)
    let spfResultsFrom = tnx.results.get('spf');
    let spfResultsHelo = tnx.results.get('spf');
    if (spfResultsFrom && spfResultsFrom.scope === 'mfrom' && spfResultsFrom.result === 'Pass') {
        verificationResults.spf = tools.normalizeDomain(spfResultsFrom.domain);
    } else if (spfResultsHelo && spfResultsHelo.scope === 'helo' && spfResultsHelo.result === 'Pass') {
        verificationResults.spf = tools.normalizeDomain(spfResultsHelo.domain);
    }

    // find domain that DKIM signed this message. Prefer header from, otherwise use envelope from
    if (tnx.notes.dkim_results) {
        let dkimResults = Array.isArray(tnx.notes.dkim_results) ? tnx.notes.dkim_results : [].concat(tnx.notes.dkim_results || []);

        let envelopeFrom = tnx.notes.sender;
        let headerFrom = plugin.getHeaderFrom(tnx);

        let envelopeDomain = (envelopeFrom && envelopeFrom.split('@').pop()) || '';
        let headerDomain = (headerFrom && headerFrom.address && headerFrom.address.split('@').pop()) || '';

        for (let dkimResult of dkimResults) {
            if (dkimResult && dkimResult.result === 'pass') {
                let domain = tools.normalizeDomain(dkimResult.domain);

                if (headerDomain && domain === headerDomain) {
                    verificationResults.dkim = headerDomain;
                    break;
                }

                if (envelopeDomain && domain === envelopeDomain) {
                    verificationResults.dkim = envelopeDomain;
                    // do not break yet, maybe header domain result also exists
                }
            }
        }

        // no mathcing domain found, use the first valid one
        if (!verificationResults.dkim && dkimResults.length) {
            verificationResults.dkim = dkimResults[0].domain;
        }
    }

    const { forwards, autoreplies, users } = tnx.notes.targets;
    let messageId = (tnx.header.get('Message-Id') || '').toString();
    let subject = (tnx.header.get('Subject') || '').toString();

    let sendLogEntry = resolution => {
        if (resolution) {
            let rspamd = tnx.results.get('rspamd');

            try {
                subject = libmime.decodeWords(subject).trim();
            } catch (E) {
                // failed to parse value
            }

            let message = {
                short_message: '[PROCESS] ' + queueId,
                _mail_action: 'process',
                _queue_id: queueId,
                _ip: remoteIp,
                _message_id: messageId.replace(/^[\s<]+|[\s>]+$/g, ''),
                _spam_score: rspamd ? rspamd.score : '',
                _spam_action: rspamd ? rspamd.action : '',
                _from: tnx.notes.sender,
                _subject: subject
            };

            Object.keys(resolution).forEach(key => {
                if (resolution[key]) {
                    message[key] = resolution[key];
                }
            });

            message._spam_tests = this.rspamdSymbols(tnx)
                .map(symbol => `${symbol.key}=${symbol.score}`)
                .join(', ');

            plugin.loggelf(message);
        }
    };

    let collector = new StreamCollect();

    let collectData = done => {
        // buffer message chunks by draining the stream
        collector.on('data', () => false); //just drain
        tnx.message_stream.once('error', err => collector.emit('error', err));
        collector.once('end', done);

        collector.once('error', err => {
            plugin.logerror('PIPEFAIL error=' + err.message, plugin, connection);
            sendLogEntry({
                full_message: err.stack,
                _error: 'pipefail processing input',
                _failure: 'yes',
                _err_code: err.code
            });
            tnx.notes.rejectCode = 'ERRQ01';
            return next(DENYSOFT, 'Failed to queue message [ERRQ01]');
        });

        tnx.message_stream.pipe(collector);
    };

    plugin.getHeaderAddresses(tnx, (err, headerAddresses) => {
        if (err) {
            sendLogEntry({
                full_message: err.stack,

                _error: 'error resolving addresses',
                _failure: 'yes',
                _err_code: err.code
            });
            tnx.notes.rejectCode = 'ERRQ02';
            return next(DENYSOFT, 'Failed to queue message [ERRQ02]');
        }

        // filter user ids that are allowed to send autoreplies
        // this way we skip sending autoreplies from forwarded addresses
        let allowAutoreply = new Set();
        headerAddresses.to.forEach(addr => {
            if (addr.user) {
                allowAutoreply.add(addr.user.toString());
            }
        });
        headerAddresses.cc.forEach(addr => {
            if (addr.user) {
                allowAutoreply.add(addr.user.toString());
            }
        });

        let forwardMessage = done => {
            if (!forwards.size) {
                // the message does not need forwarding at this point
                return collectData(done);
            }

            let rspamd = tnx.results.get('rspamd');
            if (rspamd && rspamd.score && plugin.rspamd.forwardSkip && rspamd.score >= plugin.rspamd.forwardSkip) {
                // do not forward spam messages
                plugin.loginfo('FORWARDSKIP score=' + JSON.stringify(rspamd.score) + ' required=' + plugin.rspamd.forwardSkip, plugin, connection);

                let message = {
                    short_message: '[Skip forward] ' + queueId,
                    _mail_action: 'forward',
                    _forward_skipped: 'yes',
                    _spam_score: rspamd ? rspamd.score : '',
                    _spam_action: rspamd ? rspamd.action : '',
                    _spam_allowed: plugin.rspamd.forwardSkip
                };

                message._spam_tests = this.rspamdSymbols(tnx)
                    .map(symbol => `${symbol.key}=${symbol.score}`)
                    .join(', ');

                sendLogEntry(message);

                return collectData(done);
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
                parentId: tnx.notes.id,
                reason: 'forward',

                from: tnx.notes.sender,
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
                        tnx.notes.rejectCode = 'ERRQ03';
                        return next(DENYSOFT, 'Failed to queue message [ERRQ03]');
                    }
                    return done(err, ...args);
                }

                sendLogEntry({
                    short_message: '[Queued forward] ' + queueId,
                    _mail_action: 'forward',
                    _target_queue_id: args[0].id,
                    _target_address: (targets || []).map(target => ((target && target.value) || target).toString().replace(/\?.*$/, '')).join('\n')
                });

                plugin.loggelf({
                    _queue_id: args[0].id,

                    short_message: '[QUEUED] ' + args[0].id,

                    _parent_queue_id: queueId,
                    _from: tnx.notes.sender,
                    _to: (targets || []).map(target => ((target && target.value) || target).toString().replace(/\?.*$/, '')).join('\n'),

                    _queued: 'yes',
                    _forwarded: 'yes',

                    _interface: 'mx'
                });

                plugin.loginfo('QUEUED FORWARD queue-id=' + args[0].id, plugin, connection);

                done(err, args && args[0] && args[0].id);
            });

            if (message) {
                tnx.message_stream.once('error', err => message.emit('error', err));
                message.once('error', err => {
                    plugin.logerror('QUEUEERROR Failed to retrieve message. error=' + err.message, plugin, connection);
                    sendLogEntry({
                        full_message: err.stack,

                        _error: 'failed to retrieve message from input',
                        _failure: 'yes',
                        _err_code: err.code
                    });
                    tnx.notes.rejectCode = 'ERRQ04';
                    return next(DENYSOFT, 'Failed to queue message [ERRQ04]');
                });

                // pipe the message to the collector object to gather message chunks for further processing
                tnx.message_stream.pipe(collector).pipe(message);
            }
        };

        let sendAutoreplies = done => {
            if (!autoreplies.size) {
                return done();
            }

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
                        queueId,
                        maildrop: plugin.maildrop,
                        sender: tnx.notes.sender,
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
                                plugin.lognotice('AUTOREPLY ERROR target=' + tnx.notes.sender + ' error=' + err.message, plugin, connection);
                                return processNext();
                            }
                            return done(err, ...args);
                        }

                        sendLogEntry({
                            short_message: '[Queued autoreply] ' + queueId,
                            _mail_action: 'autoreply',
                            _target_queue_id: args[0].id,
                            _target_address: addressData.address
                        });

                        plugin.loggelf({
                            _queue_id: args[0].id,

                            short_message: '[QUEUED] ' + args[0].id,

                            _parent_queue_id: queueId,
                            _from: addressData.address,
                            _to: addressData.address,

                            _queued: 'yes',
                            _autoreply: 'yes',

                            _interface: 'mx'
                        });

                        plugin.loginfo('QUEUED AUTOREPLY target=' + tnx.notes.sender + ' queue-id=' + args[0].id, plugin, connection);
                        return done(err, ...args);
                    }
                );
            };
            processNext();
        };

        // update rate limit counters for all recipients
        let updateRateLimits = done => {
            let rateKeys = tnx.notes.rateKeys || [];
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

                    let rspamd = tnx.results.get('rspamd');
                    let rcptData = userList[stored++];
                    let recipient = rcptData.recipient;
                    let userData = rcptData.userData;

                    plugin.logdebug(plugin, 'Filtering message for ' + recipient, plugin, connection);
                    plugin.filterHandler.process(
                        {
                            mimeTree: prepared && prepared.mimeTree,
                            maildata: prepared && prepared.maildata,
                            user: userData,
                            sender: tnx.notes.sender,
                            recipient,
                            chunks: collector.chunks,
                            chunklen: collector.chunklen,
                            disableAutoreply: !allowAutoreply.has(userData._id.toString()),
                            verificationResults,
                            meta: {
                                transactionId: queueId,
                                source: 'MX',
                                from: tnx.notes.sender,
                                to: [recipient],
                                origin: remoteIp,
                                transhost,
                                transtype: tnx.notes.transmissionType,
                                spamScore: rspamd ? rspamd.score : false,
                                spamAction: rspamd ? rspamd.action : false,
                                time: new Date()
                            }
                        },
                        (err, response, preparedResponse) => {
                            if (!prepared && preparedResponse) {
                                // reuse parsed message structure
                                prepared = preparedResponse;
                            }

                            if (err) {
                                sendLogEntry({
                                    full_message: err.stack,

                                    _user: userData._id.toString(),
                                    _address: recipient,

                                    _no_store: 'yes',
                                    _error: 'failed to store message',
                                    _failure: 'yes',
                                    _err_code: err.code
                                });

                                // might be an isse to reject if some recipients were already processed
                                plugin.loginfo('DEFERRED rcpt=' + recipient + ' error=' + err.message, plugin, connection);
                                tnx.notes.rejectCode = 'ERRQ05';
                                return next(DENYSOFT, 'Failed to queue message [ERRQ05]');
                            }

                            let targetMailbox;
                            let targetId;
                            let isSpam = false;
                            let filterMessages = [];
                            let matchingFilters;
                            if (response && response.filterResults && response.filterResults.length) {
                                response.filterResults.forEach(entry => {
                                    if (entry.forward) {
                                        sendLogEntry({
                                            short_message: '[Queued forward] ' + queueId,
                                            _user: userData._id.toString(),
                                            _to: recipient,
                                            _mail_action: 'forward',
                                            _target_queue_id: entry['forward-queue-id'],
                                            _target_address: entry.forward
                                        });

                                        plugin.loggelf({
                                            short_message: '[QUEUED] ' + entry['forward-queue-id'],
                                            _queue_id: entry['forward-queue-id'],

                                            _parent_queue_id: queueId,
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
                                            short_message: '[Queued autoreply] ' + queueId,
                                            _mail_action: 'autoreply',
                                            _user: userData._id.toString(),
                                            _to: recipient,
                                            _target_queue_id: entry['autoreply-queue-id'],
                                            _target_address: entry.autoreply
                                        });

                                        plugin.loggelf({
                                            short_message: '[QUEUED] ' + entry['autoreply-queue-id'],
                                            _queue_id: entry['autoreply-queue-id'],

                                            _parent_queue_id: queueId,
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
                                        filterMessages.push('Spam');
                                        return;
                                    }

                                    if (entry.mailbox && entry.id) {
                                        targetMailbox = entry.mailbox && { mailbox: entry.mailbox, path: entry.path, uid: entry.uid };
                                        targetId = entry.id;
                                        return;
                                    }

                                    if (entry.matchingFilters && entry.matchingFilters.length) {
                                        matchingFilters = entry.matchingFilters;
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
                                tnx.notes.rejectCode = response.error.code;

                                if (response.error.code === 'DroppedByPolicy') {
                                    sendLogEntry({
                                        full_message: response.error.message,

                                        _user: userData._id.toString(),
                                        _to: recipient,
                                        _filter: filterMessages.length ? filterMessages.join('\n') : '',
                                        _filter_is_spam: isSpam ? 'yes' : 'no',
                                        _filters_matching: matchingFilters ? matchingFilters.join('\n') : '',

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

                                    // appears as accepted
                                    return setImmediate(storeNext);
                                }

                                sendLogEntry({
                                    full_message: response.error.stack,

                                    _user: userData._id.toString(),
                                    _to: recipient,
                                    _filter: filterMessages.length ? filterMessages.join('\n') : '',
                                    _filter_is_spam: isSpam ? 'yes' : 'no',
                                    _filters_matching: matchingFilters ? matchingFilters.join('\n') : '',

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

                                return next(DENYSOFT, response.error.message);
                            }

                            sendLogEntry({
                                _user: userData._id.toString(),
                                _to: recipient,
                                _stored: 'yes',
                                _store_result: response.response,
                                _filter: filterMessages.length ? filterMessages.join('\n') : '',
                                _filter_is_spam: isSpam ? 'yes' : 'no',
                                _filters_matching: matchingFilters ? matchingFilters.join('\n') : '',

                                _stored_mailbox: targetMailbox && targetMailbox.mailbox,
                                _stored_path: targetMailbox && targetMailbox.path,
                                _stored_uid: targetMailbox && targetMailbox.uid,

                                _stored_id: targetId
                            });

                            plugin.loginfo(
                                'STORED rcpt=' + recipient + ' user=' + userData.address + '[' + userData._id + '] result=' + response.response,
                                plugin,
                                connection
                            );

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
    const plugin = this;

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
    const plugin = this;

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

exports.getHeaderFrom = function(tnx) {
    let fromAddresses = new Map();
    [].concat(tnx.header.get_all('From') || []).forEach(entry => {
        let walk = addresses => {
            addresses.forEach(address => {
                if (address.address) {
                    let normalized = tools.normalizeAddress(address.address, false, { removeLabel: true });
                    let uview = tools.uview(normalized);
                    try {
                        if (address.name) {
                            address.name = libmime.decodeWords(address.name).trim();
                        }
                    } catch (E) {
                        // failed to parse value
                    }
                    fromAddresses.set(uview, { address: normalized, provided: address });
                } else if (address.group) {
                    walk(address.group);
                }
            });
        };
        walk(addressparser(entry));
    });

    return Array.from(fromAddresses)
        .map(entry => entry[1])
        .shift();
};

exports.getHeaderAddresses = function(tnx, next) {
    const plugin = this;

    let toAddresses = new Map();
    let ccAddresses = new Map();
    let unique = new Set();

    [].concat(tnx.header.get_all('To') || []).forEach(entry => {
        let walk = addresses => {
            addresses.forEach(address => {
                if (address.address) {
                    let normalized = tools.normalizeAddress(address.address, false, { removeLabel: true });
                    let uview = tools.uview(normalized);
                    toAddresses.set(uview, { address: normalized, provided: address });
                    unique.add(uview);
                } else if (address.group) {
                    walk(address.group);
                }
            });
        };
        walk(addressparser(entry));
    });

    [].concat(tnx.header.get_all('Cc') || []).forEach(entry => {
        let walk = addresses => {
            addresses.forEach(address => {
                if (address.address) {
                    let normalized = tools.normalizeAddress(address.address, false, { removeLabel: true });
                    let uview = tools.uview(normalized);
                    if (!toAddresses.has(uview)) {
                        ccAddresses.set(uview, { address: normalized, provided: address });
                    }
                    unique.add(normalized);
                } else if (address.group) {
                    walk(address.group);
                }
            });
        };
        walk(addressparser(entry));
    });

    plugin.db.users
        .collection('addresses')
        .find({ addrview: { $in: Array.from(unique) } })
        .toArray((err, list) => {
            if (err) {
                return next(err);
            }

            if (list && list.length) {
                list.forEach(addressData => {
                    if (toAddresses.has(addressData.addrview)) {
                        addressData.provided = toAddresses.get(addressData.addrview).provided;
                        toAddresses.set(addressData.addrview, addressData);
                    }
                    if (ccAddresses.has(addressData.addrview)) {
                        addressData.provided = ccAddresses.get(addressData.addrview).provided;
                        ccAddresses.set(addressData.addrview, addressData);
                    }
                });
            }

            next(null, {
                to: toAddresses,
                cc: ccAddresses
            });
        });
};

exports.rspamdSymbols = function(tnx) {
    let rspamd = tnx.results.get('rspamd');
    let symbols = (rspamd && rspamd.symbols) || rspamd;

    let result = [];

    if (!symbols) {
        return result;
    }

    Object.keys(symbols).forEach(key => {
        let score;

        if (typeof symbols[key] === 'number') {
            score = symbols[key];
        } else if (typeof symbols[key] === 'object' && symbols[key] && typeof symbols[key].score === 'number') {
            score = symbols[key].score;
        } else {
            return;
        }
        if (score) {
            // filter out SYMBOL=0 keys
            result.push({ key, value: symbols[key], score });
        }
    });

    return result;
};

exports.checkRspamdBlacklist = function(tnx) {
    const plugin = this;
    let rspamd = tnx.results.get('rspamd');
    let symbols = (rspamd && rspamd.symbols) || rspamd;

    if (!symbols) {
        return false;
    }

    for (let key of plugin.rspamd.blacklist) {
        if (!(key in symbols)) {
            continue;
        }

        let score;
        if (typeof symbols[key] === 'number') {
            score = symbols[key];
        } else if (typeof symbols[key] === 'object' && symbols[key] && typeof symbols[key].score === 'number') {
            score = symbols[key].score;
        }

        if (score && score > 0) {
            return { key, value: symbols[key] };
        }
    }
    return false;
};

exports.checkRspamdSoftlist = function(tnx) {
    const plugin = this;
    let rspamd = tnx.results.get('rspamd');
    let symbols = (rspamd && rspamd.symbols) || rspamd;

    if (!symbols) {
        return false;
    }

    for (let key of plugin.rspamd.softlist) {
        if (!(key in symbols)) {
            continue;
        }

        let score;
        if (typeof symbols[key] === 'number') {
            score = symbols[key];
        } else if (typeof symbols[key] === 'object' && symbols[key] && typeof symbols[key].score === 'number') {
            score = symbols[key].score;
        }

        if (score && score > 0) {
            return { key, value: symbols[key] };
        }
    }
    return false;
};

exports.dsnSpamResponse = function(tnx, key) {
    const plugin = this;
    let message = plugin.rspamd.responses[key] || defaultSpamRejectMessage;

    let domain;
    message = message.toString().replace(/\{host\}/gi, () => {
        if (domain) {
            return domain;
        }
        let headerFrom = plugin.getHeaderFrom(tnx) || tnx.notes.sender || '';
        domain = (headerFrom && headerFrom.address && headerFrom.address.split('@').pop()) || '-';
        return domain;
    });

    return DSN.create(550, message, 7, 1);
};
