'use strict';

const mongodb = require('mongodb');
const Redis = require('ioredis');
const MongoClient = mongodb.MongoClient;
const UserHandler = require('wildduck/lib/user-handler');
const MessageHandler = require('wildduck/lib/message-handler');
const tools = require('wildduck/lib/tools');

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

module.exports.connect = (redis, config, callback) => {
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
                    if (redis) {
                        response.redis = redis;
                    } else {
                        response.redis = new Redis(tools.redisConfig(config.redis));
                    }

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
