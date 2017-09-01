'use strict';

const mongodb = require('mongodb');
const redis = require('redis');
const MongoClient = mongodb.MongoClient;
const UserHandler = require('wildduck/lib/user-handler');
const MessageHandler = require('wildduck/lib/message-handler');

let getDBConnection = (main, config, callback) => {
    if (main) {
        if (!config) {
            return callback(null, main);
        }
        if (config && !/[:/]/.test(config)) {
            return callback(null, main.db(config));
        }
    }
    MongoClient.connect(config, (err, db) => {
        if (err) {
            return callback(err);
        }
        return callback(null, db);
    });
};

module.exports.connect = (config, callback) => {
    let response = {};
    getDBConnection(false, config.mongo.url, (err, db) => {
        if (err) {
            return callback(err);
        }
        response.database = db;
        getDBConnection(db, config.mongo.gridfs, (err, db) => {
            if (err) {
                return callback(err);
            }
            response.gridfs = db;
            getDBConnection(db, config.mongo.users, (err, db) => {
                if (err) {
                    return callback(err);
                }
                response.users = db;
                getDBConnection(db, config.mongo.sender, (err, db) => {
                    if (err) {
                        return callback(err);
                    }
                    response.senderDb = db;

                    response.redisConfig = redisConfig(config.mongo.redis);
                    response.redis = redis.createClient(response.redisConfig);

                    response.messageHandler = new MessageHandler({
                        database: response.database,
                        users: response.users,
                        redis: response.redis,
                        gridfs: response.gridfs,
                        attachments: config.attachments
                    });

                    response.userHandler = new UserHandler({
                        database: response.database,
                        users: response.users,
                        redis: response.redis,
                        gridfs: response.gridfs,
                        authlogExpireDays: Number(config.log.authlogExpireDays) || 30
                    });

                    return callback(null, response);
                });
            });
        });
    });
};

// returns a redis config object with a retry strategy
function redisConfig(defaultConfig) {
    let response = {};

    if (typeof defaultConfig === 'string') {
        defaultConfig = {
            url: defaultConfig
        };
    }

    Object.keys(defaultConfig || {}).forEach(key => {
        response[key] = defaultConfig[key];
    });
    if (!response.hasOwnProperty('retry_strategy')) {
        response.retry_strategy = options => {
            if (options.error && options.error.code === 'ECONNREFUSED') {
                // End reconnecting on a specific error and flush all commands with a individual error
                return new Error('The server refused the connection');
            }

            if (options.total_retry_time > 1000 * 60 * 60) {
                // End reconnecting after a specific timeout and flush all commands with a individual error
                return new Error('Retry time exhausted');
            }

            if (options.attempt > 10) {
                // End reconnecting with built in error
                return undefined; // eslint-disable-line no-undefined
            }

            // reconnect after
            return Math.min(options.attempt * 100, 3000);
        };
    }

    return response;
}
