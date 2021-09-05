'use strict';

const mongodb = require('mongodb');
const Redis = require('ioredis');
const MongoClient = mongodb.MongoClient;
const UserHandler = require('wildduck/lib/user-handler');
const MessageHandler = require('wildduck/lib/message-handler');
const { SettingsHandler } = require('wildduck/lib/settings-handler');
const counters = require('wildduck/lib/counters');
const tools = require('wildduck/lib/tools');

let getDBConnection = (main, config, callback) => {
    if (main) {
        if (!config) {
            return callback(null, false);
        }
        if (config && !/[:/]/.test(config)) {
            return callback(null, main.db(config));
        }
    }

    MongoClient.connect(
        config,
        {
            useNewUrlParser: true,
            useUnifiedTopology: true
        },
        (err, db) => {
            if (err) {
                return callback(err);
            }
            if (main && db.s && db.s.options && db.s.options.dbName) {
                db = db.db(db.s.options.dbName);
            }
            return callback(null, db);
        }
    );
};

module.exports.connect = (redis, config, callback) => {
    let response = {};
    // main connection
    getDBConnection(false, config.mongo.url, (err, db) => {
        if (err) {
            return callback(err);
        }

        if (db.s && db.s.options && db.s.options.dbName) {
            response.database = db.db(db.s.options.dbName);
        } else {
            response.database = db;
        }

        getDBConnection(db, config.mongo.gridfs, (err, gdb) => {
            if (err) {
                return callback(err);
            }
            response.gridfs = gdb || response.database;

            getDBConnection(db, config.mongo.users, (err, udb) => {
                if (err) {
                    return callback(err);
                }
                response.users = udb || response.database;

                getDBConnection(db, config.mongo.sender, (err, sdb) => {
                    if (err) {
                        return callback(err);
                    }
                    response.senderDb = sdb || response.database;

                    response.redis = new Redis(tools.redisConfig(config.redis));

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
                        gridfs: response.gridfs
                    });

                    response.settingsHandler = new SettingsHandler({ db: response.database });

                    response.ttlcounter = counters(response.redis).ttlcounter;

                    return callback(null, response);
                });
            });
        });
    });
};
