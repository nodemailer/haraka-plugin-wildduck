'use strict';

// disable config loading by WildDuck
process.env.DISABLE_WILD_CONFIG = 'true';

const os = require('os');
const db = require('./lib/db');
const DSN = require('haraka-dsn');
const dns = require('dns');
const ObjectId = require('mongodb').ObjectId;
const punycode = require('punycode.js');
const SRS = require('srs.js');
const counters = require('wildduck/lib/counters');
const tools = require('wildduck/lib/tools');
const StreamCollect = require('./lib/stream-collect');
const Maildropper = require('wildduck/lib/maildropper');
const FilterHandler = require('wildduck/lib/filter-handler');
const BimiHandler = require('wildduck/lib/bimi-handler');
const autoreply = require('wildduck/lib/autoreply');
const wdErrors = require('wildduck/lib/errors');
const Gelf = require('gelf');
const addressparser = require('nodemailer/lib/addressparser');
const libmime = require('libmime');
const { promisify } = require('util');

const { mail: hookMail, dataPost: hookDataPost } = require('./lib/hooks');

DSN.rcpt_too_fast = () =>
    DSN.create(
        450,
        'The user you are trying to contact is receiving mail at a rate that\nprevents additional messages from being delivered. Please resend your\nmessage at a later time. If the user is able to receive mail at that\ntime, your message will be delivered.',
        2,
        1
    );

// default mbox_full is 450
DSN.mbox_full_554 = () => DSN.create(554, 'Mailbox full', 2, 2);

const defaultSpamRejectMessage =
    'Our system has detected that this message is likely unsolicited mail.\nTo reduce the amount of spam this message has been blocked.';

exports.register = function () {
    const plugin = this;
    plugin.logdebug('Initializing WildDuck plugin.');
    plugin.load_wildduck_cfg();

    plugin.register_hook('init_master', 'open_database');
    plugin.register_hook('init_child', 'open_database');

    plugin.resolver = async (name, rr) => await dns.promises.resolve(name, rr);
};

exports.load_wildduck_cfg = function () {
    this.cfg = this.config.get(
        'wildduck.yaml',
        {
            booleans: ['attachments.decodeBase64', 'sender.enabled']
        },
        () => {
            this.load_wildduck_cfg();
        }
    );
};

exports.open_database = function (next, server) {
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
                      plugin.loginfo('GELF ' + JSON.stringify(message));
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
        message._interface = message._interface || 'mx';

        Object.keys(message).forEach(key => {
            if (!message[key]) {
                delete message[key];
            }
        });

        plugin.gelf.emit('gelf.log', message);
    };

    const createConnection = done => {
        db.connect(server.notes.redis, plugin.cfg, (err, db) => {
            if (err) {
                return done(err);
            }
            plugin.db = db;
            plugin.ttlcounter = counters(db.redis).ttlcounter;
            plugin.ttlcounterAsync = promisify(plugin.ttlcounter);

            plugin.db.messageHandler.loggelf = message => plugin.loggelf(message);
            plugin.db.userHandler.loggelf = message => plugin.loggelf(message);

            plugin.maildrop = new Maildropper({ db, ...plugin.cfg.sender });

            plugin.filterHandler = new FilterHandler({
                db,
                sender: plugin.cfg.sender,
                messageHandler: plugin.db.messageHandler,
                loggelf: message => plugin.loggelf(message)
            });

            plugin.bimiHandler = BimiHandler.create({
                database: db.database,
                loggelf: message => plugin.loggelf(message)
            });

            done();
        });
    };

    let returned = false;
    const tryCreateConnection = () => {
        createConnection(err => {
            if (err) {
                if (!returned) {
                    plugin.logcrit('Database connection failed. ' + err.message);
                    returned = true;
                    next();
                }
                // keep trying to open up the DB connection
                setTimeout(tryCreateConnection, 2 * 1000);
                return;
            }

            plugin.loginfo('Database connection opened');
            if (!returned) {
                returned = true;
                next();
            }
        });
    };

    tryCreateConnection();
};

exports.normalize_address = function (address) {
    if (/^SRS\d+=/i.test(address.user)) {
        // Try to fix case-mangled addresses where the intermediate MTA converts user part to lower case
        // and thus breaks hash verification
        const localAddress = address.user
            // ensure that address starts with uppercase SRS
            .replace(/^SRS\d+=/i, val => val.toUpperCase())
            // ensure that the first entity that looks like SRS timestamp is uppercase
            .replace(/([-=+][0-9a-f]{4})(=[A-Z2-7]{2}=)/i, (str, sig, ts) => sig + ts.toUpperCase());

        return localAddress + '@' + punycode.toUnicode(address.host.toLowerCase().trim());
    }

    return tools.normalizeAddress(address.address());
};

exports.increment_forward_counters = async function (connection) {
    const plugin = this;
    const txn = connection.transaction;

    if (!txn || !txn.notes || !txn.notes.targets || !txn.notes.targets.forwardCounters) {
        return false;
    }

    const { forwardCounters } = txn.notes.targets;

    for (const [key, { increment, limit }] of forwardCounters.entries()) {
        try {
            const ttlres = await plugin.ttlcounterAsync('wdf:' + key, increment, limit, false);
            connection.loginfo(plugin, `Forward counter updated for ${key} (${increment}/${limit}): ${JSON.stringify(ttlres)}`);
        } catch (err) {
            connection.logerror(plugin, err.message);
        }
    }
};

exports.handle_forwarding_address = async function (connection, address, addressData) {
    const plugin = this;
    const txn = connection.transaction;

    if (!txn || !txn.notes || !txn.notes.targets || !txn.notes.targets.forwardCounters) {
        connection.logerror(plugin, 'Empty transaction, can not forward');
        return false;
    }

    const { forwards, autoreplies, /*users,*/ forwardCounters } = txn.notes.targets;

    const forwardLimit = addressData.forwards || txn.notes.settings['const:max:forwards'];

    let limitResult;
    try {
        limitResult = await plugin.ttlcounterAsync(
            'wdf:' + addressData._id.toString(),
            0, //addressData.targets.length,
            forwardLimit,
            false
        );
    } catch (err) {
        // failed checks
        err.resolution = {
            full_message: err.stack,
            _forward: 'yes',
            _rate_limit: 'yes',
            _selector: 'user',

            _failure: 'yes',
            _error: 'rate limit check failed',
            _err_code: err.code
        };
        err.code = err.code || 'RateLimit';
        throw err;
    }

    if (!limitResult.success) {
        connection.lognotice(
            'RATELIMITED target=' +
                addressData.address +
                ' key=' +
                addressData._id +
                ' limit=' +
                addressData.forwards +
                ' value=' +
                limitResult.value +
                ' ttl=' +
                limitResult.ttl,
            plugin,
            connection
        );

        const error = new Error('Rate limit hit');
        error.resolution = {
            _forward: 'yes',
            _rate_limit: 'yes',
            _selector: 'user',
            _error: 'too many attempts'
        };
        txn.notes.rejectCode = 'RATE_LIMIT';

        error.responseAction = DENY;
        error.responseMessage = DSN.rcpt_too_fast();
        throw error;
    }

    if (addressData.forwardedDisabled) {
        // forwarded address is disabled for whatever reason'
        const error = new Error('Mailbox disabled');

        error.resolution = {
            _address: addressData._id.toString(),
            _error: 'disabled forwarded address',
            _disabled_forwarded: 'yes'
        };
        txn.notes.rejectCode = 'MBOX_DISABLED';

        error.responseAction = DENY;
        error.responseMessage = DSN.mbox_disabled();
        throw error;
    }

    connection.loginfo(
        plugin,
        'FORWARDING rcpt=' +
            address +
            ' address=' +
            addressData.address +
            '[' +
            addressData._id +
            ']' +
            ' target=' +
            addressData.targets.map(target => ((target && target.value) || target).toString().replace(/\?.*$/, '')).join(', ')
    );

    if (addressData.autoreply) {
        autoreplies.set(addressData.addrview, addressData);
    }

    const forwardTargets = [];
    for (const targetData of addressData.targets) {
        if (targetData.type === 'relay') {
            // relay is not rate limited
            targetData.recipient = addressData.address || address;

            // Do not use `targetData.value` alone as it might be the same for multiple recipients
            forwards.set(`${targetData.recipient}:${targetData.value}`, targetData);

            forwardTargets.push(targetData.recipient + ':' + (targetData.value || '').toString().replace(/\?.*$/, ''));
            continue;
        } else {
            if (targetData.type !== 'mail') {
                forwardTargets.push(address + ':' + targetData.value);
                targetData.recipient = address;
            } else {
                forwardTargets.push(targetData.value);
            }

            forwards.set(targetData.value, targetData);
            continue;
        }
    }

    forwardCounters.set(addressData._id.toString(), {
        increment: forwardTargets.length,
        limit: forwardLimit
    });

    txn.notes.rejectCode = false;
    return {
        resolution: {
            _forward: 'yes',
            _rcpt_accepted: 'yes',
            _forward_to: forwardTargets.join('\n') || 'empty_list'
        }
    };
};

exports.hook_deny = function (next, connection, params) {
    const plugin = this;
    const txn = connection.transaction;
    const remoteIp = connection.remote.ip;

    if (txn === null) {
        next();
        return;
    }

    const [, , , , denyParams, denyHook] = params;

    let rcpts;
    switch (denyHook) {
        case 'rcpt':
            // only a single recipient failed
            rcpts = [].concat((denyParams && denyParams[0]) || false);
            break;
        default:
            // all recipients failed
            rcpts = txn.rcpt_to || [];
            if (!rcpts.length) {
                rcpts = [false];
            }
    }

    for (const rcpt of rcpts) {
        let user;
        const address = (rcpt && rcpt.address()) || false;

        if (txn.notes.targets && txn.notes.targets.users) {
            // try to resolve user id for the recipient address
            for (const target of txn.notes.targets.users) {
                const uid = target[0];
                const info = target[1];
                if (info && info.recipient === address) {
                    user = uid;
                }
            }
        }

        const logdata = {
            short_message: '[DENY:' + txn.notes.sender + '] ' + txn.uuid,
            _mail_action: 'deny',
            _from: txn.notes.sender,
            _queue_id: txn.uuid,
            _ip: remoteIp,
            _proto: txn.notes.transmissionType,
            _to: address,
            _user: user,
            _rejector: params && params[2],
            _reject_code: txn.notes.rejectCode || (params && params[2]) || 'UNKNOWN'
        };

        const headerFrom = plugin.getHeaderFrom(txn);
        if (headerFrom) {
            logdata._header_from = headerFrom.address;
            logdata._header_from_name = headerFrom.provided && headerFrom.provided.name;

            let fromHeadersValue = txn.header.get_all('From').join('; ');

            try {
                fromHeadersValue = libmime.decodeWords(fromHeadersValue);
            } catch {
                // return as is
            }

            logdata._header_from_value = fromHeadersValue;
        }

        const err = params && params[1];
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

exports.hook_max_data_exceeded = function (next, connection) {
    const plugin = this;

    const txn = connection.transaction;
    const remoteIp = connection.remote.ip;

    if (txn === null) {
        next();
        return;
    }

    let rcpts = txn.rcpt_to || [];
    if (!rcpts.length) {
        rcpts = [false];
    }

    for (const rcpt of rcpts) {
        let user;
        const address = (rcpt && rcpt.address()) || false;

        if (txn.notes.targets && txn.notes.targets.users) {
            // try to resolve user id for the recipient address
            for (const target of txn.notes.targets.users) {
                const uid = target[0];
                const info = target[1];
                if (info && info.recipient === address) {
                    user = uid;
                }
            }
        }

        const logdata = {
            short_message: '[DENY:' + txn.notes.sender + '] ' + txn.uuid,
            _mail_action: 'deny',
            _from: txn.notes.sender,
            _queue_id: txn.uuid,
            _ip: remoteIp,
            _proto: txn.notes.transmissionType,
            _to: address,
            _user: user,
            _reject_code: 'max_data_exceeded'
        };

        plugin.loggelf(logdata);
    }

    next();
};

exports.init_wildduck_transaction = async function (connection) {
    const txn = connection.transaction;

    // could be false on rcpt hook if mail hook didn't run
    if (txn.notes.id) return;

    txn.notes.id = new ObjectId();
    txn.notes.rateKeys = [];
    txn.notes.targets = {
        users: new Map(),
        forwards: new Map(),
        recipients: new Set(),
        autoreplies: new Map(),
        forwardCounters: new Map()
    };

    txn.notes.transmissionType = []
        .concat(connection.greeting === 'EHLO' ? 'E' : [])
        .concat('SMTP')
        .concat(connection.tls_cipher ? 'S' : [])
        .join('');

    try {
        txn.notes.settings = await this.db.settingsHandler.getMulti(['const:max:storage', 'const:max:recipients', 'const:max:forwards']);
    } catch (err) {
        connection.logerror(this, err);
    }
};

exports.hook_mail = function (next, connection, params) {
    const plugin = this;

    plugin.init_wildduck_transaction(connection).then(() => {
        hookMail(plugin, connection, params)
            .then(() => {
                next();
            })
            .catch(err => next(err.smtpAction || DENYSOFT, err.message));
    });
};

exports.hook_data_post = function (next, connection) {
    return hookDataPost(next, this, connection);
};

exports.hook_rcpt = function (next, connection, params) {
    const plugin = this;
    const txn = connection.transaction;

    let tryCount = 0;
    let tryTimer = false;
    let returned = false;
    let waitTimeout = false;

    const runHandler = () => {
        clearTimeout(tryTimer);
        plugin.init_wildduck_transaction(connection).then(() => {
            plugin.real_rcpt_handler(
                (...args) => {
                    clearTimeout(waitTimeout);
                    if (returned) {
                        return;
                    }
                    returned = true;
                    const err = args && args[0];
                    if (err && /Error$/.test(err.name)) {
                        connection.logerror(plugin, err.message);
                        txn.notes.rejectCode = 'ERRC01';
                        return next(DENYSOFT, 'Failed to process recipient, try again [ERRC01]');
                    }
                    next(...args);
                },
                connection,
                params
            );
        });
    };

    // rcpt check requires access to the db which might not be available yet
    const runCheck = () => {
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
            txn.notes.rejectCode = 'ERRC02';
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
        txn.notes.rejectCode = 'ERRC03';
        return next(DENYSOFT, 'Failed to process recipient, try again [ERRC03]');
    }, 8 * 1000);

    runCheck();
};

exports.real_rcpt_handler = function (next, connection, params) {
    const plugin = this;
    const txn = connection.transaction;
    const remoteIp = connection.remote.ip;

    const { recipients, forwards, users } = txn.notes.targets;

    const rcpt = params[0];
    if (/\*/.test(rcpt.user)) {
        // Using * is not allowed in addresses
        txn.notes.rejectCode = 'NO_SUCH_USER';
        return next(DENY, DSN.no_such_user());
    }

    const address = plugin.normalize_address(rcpt);

    recipients.add(address);

    let resolution = false;
    const hookDone = (...args) => {
        if (resolution) {
            const message = {
                short_message: '[RCPT TO:' + rcpt.address() + '] ' + txn.uuid,
                _mail_action: 'rcpt_to',
                _from: txn.notes.sender,
                _to: rcpt.address(),
                _queue_id: txn.uuid,
                _ip: remoteIp,
                _proto: txn.notes.transmissionType
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

    connection.logdebug(plugin, 'Checking validity of ' + address);

    if (/^SRS\d+=/.test(address)) {
        let reversed = false;
        try {
            reversed = plugin.srsRewriter.reverse(address.substr(0, address.indexOf('@')));
            const toDomain = punycode.toASCII((reversed[1] || '').toString().toLowerCase().trim());

            if (!toDomain) {
                connection.logerror(plugin, 'SRS FAILED rcpt=' + address + ' error=Missing domain');
                resolution = {
                    _srs: 'yes',
                    _error: 'missing domain'
                };
                txn.notes.rejectCode = 'NO_SUCH_USER';
                return hookDone(DENY, DSN.no_such_user());
            }

            reversed = reversed.join('@');
        } catch (err) {
            connection.logerror(plugin, 'SRS FAILED rcpt=' + address + ' error=' + err.message);
            resolution = {
                full_message: err.stack,
                _srs: 'yes',

                _failure: 'yes',
                _error: 'srs check failed',
                _err_code: err.code
            };
            txn.notes.rejectCode = 'NO_SUCH_USER';
            return hookDone(DENY, DSN.no_such_user());
        }

        if (reversed) {
            // accept SRS rewritten address
            const key = reversed;
            const selector = 'rcpt';
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
                    txn.notes.rejectCode = 'RATE_LIMIT';
                    return hookDone(DENYSOFT, DSN.rcpt_too_fast());
                }

                // update rate limit for this address after delivery
                txn.notes.rateKeys.push({ selector, key });

                connection.loginfo(plugin, `SRS USING rcpt=${address} target=${reversed}`);

                forwards.set(reversed, { type: 'mail', value: reversed, recipient: rcpt.address() });

                resolution = {
                    _srs: 'yes',
                    _rcpt_accepted: 'yes',
                    _forward_to: reversed
                };

                txn.notes.rejectCode = false;
                return hookDone(OK);
            });
        }
    }

    const checkIpRateLimit = (userData, done) => {
        if (!remoteIp) {
            return done();
        }

        const key = remoteIp + ':' + userData._id.toString();
        const selector = 'rcptIp';
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
                txn.notes.rejectCode = 'RATE_LIMIT';
                return hookDone(DENYSOFT, DSN.rcpt_too_fast());
            }

            // update rate limit for this address after delivery
            txn.notes.rateKeys.push({ selector, key });

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
                targets: true, // only forwarded address has `targets` set
                forwardedDisabled: true // only forwarded address has `targets` set
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

            if (addressData && addressData.address && addressData.address.includes('*')) {
                // wildcard/catchall address received email
                const originalRcptHeaderName = plugin.cfg?.originalRcptHeader || 'X-Original-Rcpt';
                txn.add_header(originalRcptHeaderName, address);
            }

            if (addressData && addressData.targets) {
                return plugin
                    .handle_forwarding_address(connection, address, addressData)
                    .then(result => {
                        if (result && result.resolution) {
                            resolution = result.resolution;
                        }
                        hookDone(OK);
                    })
                    .catch(err => {
                        if (err.resolution) {
                            resolution = err.resolution;
                        }
                        if (err.responseAction) {
                            return hookDone(err.responseAction, err.responseMessage || err);
                        } else {
                            return hookDone(err);
                        }
                    });
            }

            if (!addressData || !addressData.user) {
                connection.logdebug(plugin, 'No such user ' + address);
                resolution = {
                    _error: 'no such user',
                    _unknown_user: 'yes'
                };
                txn.notes.rejectCode = 'NO_SUCH_USER';
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
                    quota: true,
                    tagsview: true,
                    mtaRelay: true
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
                            _unknown_user: 'yes'
                        };
                        txn.notes.rejectCode = 'NO_SUCH_USER';
                        return hookDone(DENY, DSN.no_such_user());
                    }

                    if (userData.disabled) {
                        // user is disabled for whatever reason
                        resolution = {
                            _user: userData._id.toString(),
                            _error: 'disabled user',
                            _disabled_user: 'yes'
                        };
                        txn.notes.rejectCode = 'MBOX_DISABLED';
                        return hookDone(DENY, DSN.mbox_disabled());
                    }

                    // max quota for the user
                    const quota = userData.quota || txn.notes.settings['const:max:storage'];
                    if (userData.storageUsed && quota <= userData.storageUsed) {
                        // can not deliver mail to this user, over quota
                        resolution = {
                            _user: userData._id.toString(),
                            _error: 'user over quota',
                            _over_quota: 'yes',
                            _max_quota: quota,
                            _quota_source: userData.quota ? 'user' : 'config',
                            _storage_used: userData.storageUsed,
                            _default_address: rcpt.address() !== userData.address ? userData.address : ''
                        };
                        txn.notes.rejectCode = 'MBOX_FULL';
                        return hookDone(DENY, DSN.mbox_full_554());
                    }

                    checkIpRateLimit(userData, () => {
                        const key = userData._id.toString();
                        const selector = 'rcpt';
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
                                txn.notes.rejectCode = 'RATE_LIMIT';
                                return hookDone(DENYSOFT, DSN.rcpt_too_fast());
                            }

                            connection.loginfo(plugin, 'RESOLVED rcpt=' + rcpt.address() + ' user=' + userData.address + '[' + userData._id + ']');

                            // update rate limit for this address after delivery
                            txn.notes.rateKeys.push({ selector, key, limit: userData.receivedMax });

                            users.set(userData._id.toString(), {
                                userData,
                                recipient: rcpt.address()
                            });

                            resolution = {
                                _user: userData._id.toString(),
                                _rcpt_accepted: 'yes',
                                _default_address: rcpt.address() !== userData.address ? userData.address : ''
                            };
                            txn.notes.rejectCode = false;
                            hookDone(OK);
                        });
                    });
                }
            );
        }
    );
};

exports.hook_queue = function (next, connection) {
    const plugin = this;
    const txn = connection.transaction;
    const queueId = txn.uuid;
    const remoteIp = connection.remote.ip;
    const { forwards, autoreplies, users } = txn.notes.targets;

    const transhost = connection.hello.host;

    const blacklisted = this.checkRspamdBlacklist(txn);
    if (blacklisted) {
        // can not send DSN object for hook_queue as it is converted to [object Object]
        txn.notes.rejectCode = blacklisted.key;
        return next(DENY, plugin.dsnSpamResponse(txn, blacklisted.key).reply);
    }

    const softlisted = this.checkRspamdSoftlist(txn);
    if (softlisted) {
        // can not send DSN object for hook_queue as it is converted to [object Object]
        txn.notes.rejectCode = softlisted.key;
        return next(DENYSOFT, plugin.dsnSpamResponse(txn, softlisted.key).reply);
    }

    // results about verification (TLS, SPF, DKIM)
    const verificationResults = {
        tls: false,
        spf: false,
        dkim: false,
        arc: false,
        bimi: false
    };

    const tlsResults = connection.results.get('tls');
    if (tlsResults && tlsResults.enabled) {
        verificationResults.tls = tlsResults.cipher;
    }

    const envelopeFrom = txn.notes.sender;
    const headerFrom = plugin.getHeaderFrom(txn);

    // SPF result
    if (txn.notes.spfResult?.status?.result === 'pass' && txn.notes.spfResult?.domain) {
        verificationResults.spf = txn.notes.spfResult?.domain;
    }

    // DKIM result
    // Sort signatures, prefer passing and aligned ones
    const dkimResults = (txn.notes.dkimResult?.results || []).sort((a, b) => {
        if (a.status === 'pass' && b.status !== 'pass') {
            return -1;
        }
        if (a.status !== 'pass' && b.status === 'pass') {
            return 1;
        }
        if (a.status?.aligned && !b.status?.aligned) {
            return -1;
        }
        if (!a.status?.aligned && b.status?.aligned) {
            return 1;
        }
        if (a.status?.aligned && b.status?.aligned) {
            return a.status?.aligned.localeCompare(b.status?.aligned);
        }
        return a.signingDomain.localeCompare(b.signingDomain);
    });

    if (dkimResults[0]?.status?.result === 'pass') {
        verificationResults.dkim = dkimResults[0]?.signingDomain;
    }

    // ARC
    if (txn.notes.arcResult?.status?.result === 'pass' && txn.notes.arcResult?.signature?.signingDomain) {
        verificationResults.arc = txn.notes.arcResult?.signature?.signingDomain;
    }

    // BIMI
    if (txn.notes.bimiResult?.status?.result === 'pass') {
        verificationResults.bimi = txn.notes.bimiResult;
    }

    const messageId = (txn.header.get('Message-Id') || '').toString();
    let subject = (txn.header.get('Subject') || '').toString();

    const sendLogEntry = resolution => {
        if (resolution) {
            const rspamd = txn.results.get('rspamd');

            try {
                subject = libmime.decodeWords(subject).trim();
            } catch (E) {
                // failed to parse value
            }

            const message = {
                short_message: '[PROCESS] ' + queueId,
                _mail_action: 'process',
                _queue_id: queueId,
                _ip: remoteIp,
                _message_id: messageId.replace(/^[\s<]+|[\s>]+$/g, ''),
                _spam_score: rspamd ? rspamd.score : '',
                _spam_action: rspamd ? rspamd.action : '',
                _from: envelopeFrom,
                _subject: subject
            };

            if (headerFrom) {
                message._header_from = headerFrom.address;
                message._header_from_name = headerFrom.provided && headerFrom.provided.name;
                message._header_from_value = txn.header.get_all('From').join('; ');
            }

            Object.keys(resolution).forEach(key => {
                if (resolution[key]) {
                    message[key] = resolution[key];
                }
            });

            message._spam_tests = this.rspamdSymbols(txn)
                .map(symbol => `${symbol.key}=${symbol.score}`)
                .join(', ');

            plugin.loggelf(message);
        }
    };

    const collector = new StreamCollect({ plugin, connection });

    const collectData = done => {
        // buffer message chunks by draining the stream
        collector.on('data', () => false); //just drain
        txn.message_stream.once('error', err => collector.emit('error', err));
        collector.once('end', done);

        collector.once('error', err => {
            connection.logerror(plugin, 'PIPEFAIL error=' + err.message);
            sendLogEntry({
                full_message: err.stack,
                _error: 'pipefail processing input',
                _failure: 'yes',
                _err_code: err.code
            });
            txn.notes.rejectCode = 'ERRQ01';
            return next(DENYSOFT, 'Failed to queue message [ERRQ01]');
        });

        txn.message_stream.pipe(collector);
    };

    const referencedUsers = plugin.getReferencedUsers(txn);

    // filter user ids that are allowed to send autoreplies
    // this way we skip sending autoreplies from forwarded addresses
    const allowAutoreply = new Set();
    referencedUsers.forEach(user => {
        allowAutoreply.add(user.userData._id.toString());
    });

    const forwardMessage = done => {
        if (!forwards.size) {
            // the message does not need forwarding at this point
            return collectData(done);
        }

        const rspamd = txn.results.get('rspamd');
        if (rspamd && rspamd.score && plugin.rspamd.forwardSkip && rspamd.score >= plugin.rspamd.forwardSkip) {
            // do not forward spam messages
            connection.loginfo(plugin, 'FORWARDSKIP score=' + JSON.stringify(rspamd.score) + ' required=' + plugin.rspamd.forwardSkip);

            const message = {
                short_message: '[Skip forward] ' + queueId,
                _mail_action: 'forward',
                _forward_skipped: 'yes',
                _spam_score: rspamd ? rspamd.score : '',
                _spam_action: rspamd ? rspamd.action : '',
                _spam_allowed: plugin.rspamd.forwardSkip
            };

            message._spam_tests = this.rspamdSymbols(txn)
                .map(symbol => `${symbol.key}=${symbol.score}`)
                .join(', ');

            sendLogEntry(message);

            return collectData(done);
        }

        const targets =
            (forwards.size &&
                Array.from(forwards).map(row => ({
                    type: row[1].type,
                    value: row[1].value,
                    recipient: row[1].recipient
                }))) ||
            false;

        let user;

        for (const availableUser of users.values()) {
            if (availableUser.userData?.address === txn.notes.sender) {
                // current user
                user = availableUser.userData;
            }
        }

        const mail = {
            parentId: txn.notes.id,
            reason: 'forward',

            from: txn.notes.sender,
            to: [],

            targets,

            interface: 'forwarder'
        };

        if (user) {
            mail.mtaRelay = user.mtaRelay || false;
        }

        const message = plugin.maildrop.push(mail, (err, ...args) => {
            if (err || !args[0]) {
                if (err) {
                    err.code = err.code || 'ERRCOMPOSE';
                    sendLogEntry({
                        short_message: '[Failed forward] ' + queueId,
                        full_message: err.stack,

                        _error: 'failed to store message',
                        _mail_action: 'forward',
                        _failure: 'yes',
                        _err_code: err.code
                    });
                }
                return done(err, ...args);
            }

            sendLogEntry({
                short_message: '[Queued forward] ' + queueId,
                _mail_action: 'forward',
                _target_queue_id: args[0].id,
                _target_address: targets.map(target => ((target && target.value) || target).toString().replace(/\?.*$/, '')).join('\n')
            });

            plugin.loggelf({
                _queue_id: args[0].id,

                short_message: '[QUEUED] ' + args[0].id,

                _parent_queue_id: queueId,
                _from: txn.notes.sender,
                _to: targets.map(target => ((target && target.value) || target).toString().replace(/\?.*$/, '')).join('\n'),

                _queued: 'yes',
                _forwarded: 'yes',

                _interface: 'mx'
            });

            connection.loginfo(plugin, 'QUEUED FORWARD queue-id=' + args[0].id);

            const next = () => done(err, args && args[0] && args[0].id);
            if (txn.notes.targets && txn.notes.targets.forwardCounters) {
                return plugin
                    .increment_forward_counters(connection)
                    .then(next)
                    .catch(err => {
                        connection.logerror(plugin, err.message);
                        next();
                    });
            }
            next();
        });

        if (message) {
            txn.message_stream.once('error', err => message.emit('error', err));
            message.once('error', err => {
                connection.logerror(plugin, 'QUEUEERROR Failed to retrieve message. error=' + err.message);
                sendLogEntry({
                    full_message: err.stack,

                    _error: 'failed to retrieve message from input',
                    _failure: 'yes',
                    _err_code: err.code
                });
                txn.notes.rejectCode = 'ERRQ04';
                return next(DENYSOFT, 'Failed to queue message [ERRQ04]');
            });

            // pipe the message to the collector object to gather message chunks for further processing
            txn.message_stream.pipe(collector).pipe(message);
        }
    };

    const sendAutoreplies = async () => {
        if (!autoreplies.size) {
            return;
        }

        const curtime = new Date();

        for (const target of autoreplies) {
            const addressData = target[1];

            const autoreplyData = addressData.autoreply;
            autoreplyData._id = autoreplyData._id || addressData._id;

            if (!autoreplyData || !autoreplyData.status) {
                continue;
            }

            if (autoreplyData.start && autoreplyData.start > curtime) {
                continue;
            }

            if (autoreplyData.end && autoreplyData.end < curtime) {
                continue;
            }

            try {
                const result = await autoreply(
                    {
                        db: plugin.db,
                        queueId,
                        maildrop: plugin.maildrop,
                        sender: txn.notes.sender,
                        recipient: addressData.address,
                        chunks: collector.chunks,
                        chunklen: collector.chunklen,
                        messageHandler: plugin.db.messageHandler
                    },
                    autoreplyData
                );

                if (!result) {
                    continue;
                }

                sendLogEntry({
                    short_message: '[Queued autoreply] ' + queueId,
                    _mail_action: 'autoreply',
                    _target_queue_id: result.id,
                    _target_address: addressData.address
                });

                plugin.loggelf({
                    _queue_id: result.id,

                    short_message: '[QUEUED] ' + result.id,

                    _parent_queue_id: queueId,
                    _from: addressData.address,
                    _to: addressData.address,

                    _queued: 'yes',
                    _autoreply: 'yes',

                    _interface: 'mx'
                });

                connection.loginfo(plugin, 'QUEUED AUTOREPLY target=' + txn.notes.sender + ' queue-id=' + result.id);
            } catch (err) {
                connection.lognotice(plugin, 'AUTOREPLY ERROR target=' + txn.notes.sender + ' error=' + err.message);
            }
        }
    };

    // update rate limit counters for all recipients
    const updateRateLimits = async () => {
        const rateKeys = txn.notes.rateKeys || [];
        for (const rateKey of rateKeys) {
            connection.logdebug(plugin, 'Rate key. key=' + JSON.stringify(rateKey));
            await plugin.updateRateLimit(plugin, connection, rateKey.selector || 'rcpt', rateKey.key, rateKey.limit);
        }
        connection.logdebug(plugin, 'Rate keys processed');
    };

    const storeMessages = async () => {
        let prepared = false;
        const userList = Array.from(users).map(e => e[1]);

        if (verificationResults.bimi) {
            // fetch BIMI logo
            const bimiResolution = {
                short_message: `[BIMI] ${verificationResults.bimi.status?.header?.d}`,
                _queue_id: queueId,
                _bimi_domain: verificationResults.bimi.status?.header?.d
            };

            try {
                const bimiData = await plugin.bimiHandler.getInfo(verificationResults.bimi);
                if (bimiData?._id) {
                    verificationResults.bimi = bimiData?._id;

                    bimiResolution._has_bimi = 'yes';
                    bimiResolution._bimi_cached_id = bimiData?._id.toString();
                    bimiResolution._bimi_type = bimiData?.type;
                    bimiResolution._bimi_url = bimiData?.url;
                    bimiResolution._bimi_source = bimiData?.source;
                } else {
                    verificationResults.bimi = false;
                    bimiResolution._has_bimi = 'no';
                }
            } catch (err) {
                //connection.logerror(plugin, 'Failed to get BIMI logo: ' + err.stack);
                verificationResults.bimi = false;

                bimiResolution._failure = 'yes';
                bimiResolution._error = err.message;
                bimiResolution._err = err.code;

                bimiResolution._bimi_source = err.source;

                if (err.details && err.details.url) {
                    bimiResolution._bimi_url = err.details.url;
                    delete err.details.url;
                }

                if (err.details) {
                    bimiResolution._bimi_data = JSON.stringify(err.details);
                }
            } finally {
                plugin.loggelf(bimiResolution);
            }
        }

        for (const rcptData of userList) {
            const rspamd = txn.results.get('rspamd');
            const recipient = rcptData.recipient;
            const userData = rcptData.userData;

            connection.logdebug(plugin, 'Filtering message for ' + recipient);
            try {
                const { response, prepared: preparedResponse } = await plugin.filterHandler.storeMessage(userData, {
                    mimeTree: prepared && prepared.mimeTree,
                    maildata: prepared && prepared.maildata,
                    user: userData,
                    mailbox: rcptData.mailbox, // might be set by an additional plugin
                    sender: txn.notes.sender,
                    recipient,
                    chunks: collector.chunks,
                    chunklen: collector.chunklen,
                    disableAutoreply: !allowAutoreply.has(userData._id.toString()),
                    verificationResults,
                    meta: {
                        transactionId: queueId,
                        source: 'MX',
                        from: txn.notes.sender,
                        to: [recipient],
                        origin: remoteIp,
                        transhost,
                        transtype: txn.notes.transmissionType,
                        spamScore: rspamd ? rspamd.score : false,
                        spamAction: rspamd ? rspamd.action : false,
                        time: new Date()
                    }
                });

                if (!prepared && preparedResponse) {
                    // reuse parsed message structure
                    prepared = preparedResponse;
                }

                if (!response) {
                    throw new Error('Missing response');
                }

                let targetMailbox;
                let targetId;
                let isSpam = false;
                const filterMessages = [];
                let matchingFilters;

                if (response.attachments && response.attachments.length) {
                    response.attachments.forEach(attachment => {
                        sendLogEntry({
                            short_message: '[ATT] ' + attachment.id,
                            _user: userData._id.toString(),
                            _to: recipient,
                            _mail_action: 'attachment',
                            _attachment_id: attachment.id,
                            _encoded_sha256: attachment.encodedSha256,
                            _filename: attachment.filename,
                            _content_type: attachment.contentType,
                            _attachment_disposition: attachment.disposition,
                            _attachment_size: attachment.size,
                            _attachment_encoding: attachment.transferEncoding,
                            _attachment_count: response.attachments.length,
                            _attachment_sha256: attachment.fileContentHash
                        });
                    });
                }

                if (response.filterResults && response.filterResults.length) {
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
                        connection.loginfo(plugin, 'FILTER ACTIONS ' + filterMessages.join(','));
                    }
                }

                if (response.error) {
                    txn.notes.rejectCode = response.error.code;

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

                        connection.loginfo(
                            plugin,
                            'DROPPED rcpt=' + recipient + ' user=' + userData.address + '[' + userData._id + '] error=' + response.error.message
                        );

                        // appears as accepted
                    } else {
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

                        connection.loginfo(
                            plugin,
                            'DEFERRED rcpt=' + recipient + ' user=' + userData.address + '[' + userData._id + '] error=' + response.error.message
                        );

                        return [DENYSOFT, response.error.message];
                    }
                } else {
                    // accepted
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

                    connection.loginfo(plugin, 'STORED rcpt=' + recipient + ' user=' + userData.address + '[' + userData._id + '] result=' + response.response);
                }
            } catch (err) {
                sendLogEntry({
                    full_message: err.stack,

                    _user: userData._id.toString(),
                    _address: recipient,

                    _no_store: 'yes',
                    _error: 'failed to store message',
                    _failure: 'yes',
                    _err_code: err.code
                });

                switch (err.code) {
                    case 15: {
                        // MongoDB overflow
                        connection.loginfo(plugin, 'REJECTED rcpt=' + recipient + ' error=' + err.message);
                        txn.notes.rejectCode = 'ERRQ07';
                        return [DENY, 'Failed to queue message, too many nested attachments [ERRQ07]'];
                    }
                    default: {
                        // might be an issue to reject if some recipients were already processed
                        connection.loginfo(plugin, 'DEFERRED rcpt=' + recipient + ' error=' + err.message);
                        txn.notes.rejectCode = 'ERRQ05';
                        return [DENYSOFT, 'Failed to queue message [ERRQ05]'];
                    }
                }
            }
        }

        await updateRateLimits();

        return [OK, 'Message processed'];
    };

    // try to forward the message. If forwarding is not needed then continues immediately
    forwardMessage(() => {
        // send autoreplies to forwarded addresses (if needed)
        sendAutoreplies()
            .catch(err => {
                connection.logerror(plugin, 'AUTOREPLY error=' + err.message);
            })
            .finally(() => {
                storeMessages()
                    .then(args => next(...args))
                    .catch(err => {
                        // should not happen, just in case
                        sendLogEntry({
                            full_message: err.stack,
                            _no_store: 'yes',
                            _error: 'failed to store message',
                            _failure: 'yes',
                            _err_code: err.code
                        });

                        connection.loginfo(plugin, 'DEFERRED error=' + err.message);
                        txn.notes.rejectCode = 'ERRQ06';
                        next(DENYSOFT, 'Failed to queue message [ERRQ06]');
                    });
            });
    });
};

// Rate limit is checked on RCPT TO
exports.checkRateLimit = function (connection, selector, key, limit, next) {
    const plugin = this;

    limit = Number(limit) || plugin.cfg.limits[selector];
    if (!limit) {
        return next(null, true);
    }

    const windowSize = plugin.cfg.limits[selector + 'WindowSize'] || plugin.cfg.limits.windowSize || 1 * 3600;

    plugin.ttlcounter('rl:' + selector + ':' + key, 0, limit, windowSize, (err, result) => {
        if (err) {
            connection.logerror(plugin, 'RATELIMITERR error=' + err.message);
            return next(err);
        }

        if (!result.success) {
            connection.lognotice(
                plugin,
                'RATELIMITED key=' + key + ' selector=' + selector + ' limit=' + limit + ' value=' + result.value + ' ttl=' + result.ttl
            );
        }

        next(null, result.success);
    });
};

// Update rate limit counters on successful delivery
exports.updateRateLimit = async (plugin, connection, selector, key, limit) => {
    limit = Number(limit) || plugin.cfg.limits[selector];
    if (!limit) {
        return true;
    }

    const windowSize = plugin.cfg.limits[selector + 'WindowSize'] || plugin.cfg.limits.windowSize || 1 * 3600;

    return new Promise((resolve, reject) => {
        plugin.ttlcounter('rl:' + selector + ':' + key, 1, limit, windowSize, (err, result) => {
            if (err) {
                connection.logerror(plugin, 'RATELIMITERR error=' + err.message);
                return reject(err);
            }

            connection.logdebug(
                plugin,
                'Rate limit key=' + key + ' selector=' + selector + ' limit=' + limit + ' value=' + result.value + ' ttl=' + result.ttl
            );

            resolve(result.success);
        });
    });
};

exports.getHeaderFrom = function (txn) {
    const fromAddresses = new Map();
    [].concat(txn.header.get_all('From') || []).forEach(entry => {
        const walk = addresses => {
            addresses.forEach(address => {
                if (address.address) {
                    const normalized = tools.normalizeAddress(address.address, false, { removeLabel: true });
                    const uview = tools.uview(normalized);
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

// Filter recipients that are referenced in message headers To: or Cc fields
exports.getReferencedUsers = function (txn) {
    const { users } = txn.notes.targets;

    const referencedUsers = new Set();

    []
        .concat(txn.header.get_all('To') || [])
        .concat(txn.header.get_all('Cc') || [])
        .forEach(entry => {
            const walk = addresses => {
                addresses.forEach(address => {
                    if (address.address) {
                        for (const user of users.values()) {
                            if (user.recipient === address.address) {
                                referencedUsers.add(user);
                                break;
                            }
                        }
                    } else if (address.group) {
                        walk(address.group);
                    }
                });
            };
            walk(addressparser(entry));
        });

    return referencedUsers;
};

exports.rspamdSymbols = function (txn) {
    const rspamd = txn.results.get('rspamd');
    const symbols = (rspamd && rspamd.symbols) || rspamd;

    const result = [];

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

exports.checkRspamdBlacklist = function (txn) {
    const plugin = this;
    const rspamd = txn.results.get('rspamd');
    const symbols = (rspamd && rspamd.symbols) || rspamd;

    if (!symbols) {
        return false;
    }

    for (const key of plugin.rspamd.blacklist) {
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

exports.checkRspamdSoftlist = function (txn) {
    const plugin = this;
    const rspamd = txn.results.get('rspamd');
    const symbols = (rspamd && rspamd.symbols) || rspamd;

    if (!symbols) {
        return false;
    }

    for (const key of plugin.rspamd.softlist) {
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

exports.dsnSpamResponse = function (txn, key) {
    const plugin = this;
    let message = plugin.rspamd.responses[key] || defaultSpamRejectMessage;

    let domain;
    message = message.toString().replace(/\{host\}/gi, () => {
        if (domain) {
            return domain;
        }
        const headerFrom = plugin.getHeaderFrom(txn) || txn.notes.sender || '';
        domain = (headerFrom && headerFrom.address && headerFrom.address.split('@').pop()) || '-';
        return domain;
    });

    return DSN.create(550, message, 7, 1);
};
