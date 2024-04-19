module.exports = {
    upgrade: true,
    reject: [
        // mongodb 5.x driver does not support callbacks, only promises
        'mongodb',

        // some api changes, need to address in the future
        'eslint'
    ]
};
