'use strict';

const { arc } = require('mailauth/lib/arc');
const { dmarc } = require('mailauth/lib/dmarc');
const { spf: checkSpf } = require('mailauth/lib/spf');
const { dkimVerify } = require('mailauth/lib/dkim/verify');
const { bimi } = require('mailauth/lib/bimi');

async function hookMail(plugin, connection, params) {
    const txn = connection?.transaction;
    if (!txn) {
        return;
    }

    // Step 1. SPF

    const from = params[0];
    txn.notes.sender = txn.notes.sender || from?.address();

    let spfResult;

    try {
        spfResult = await checkSpf({
            resolver: plugin.resolver,
            ip: connection.remote_ip, // SMTP client IP
            helo: connection.hello?.host, // EHLO/HELO hostname
            sender: txn.notes.sender, // MAIL FROM address
            mta: connection.local?.host, // MX hostname
            maxResolveCount: plugin.cfg?.auth?.dns?.maxLookups
        });
        txn.notes.spfResult = spfResult;
    } catch (err) {
        txn.notes.spfResult = { error: err };
        plugin.logerror(err, plugin, connection);
        return;
    }

    if (spfResult.header) {
        txn.add_leading_header('Received-SPF', spfResult.header.substring(spfResult.header.indexOf(':') + 1).trim());
    }

    if (spfResult.info) {
        connection.auth_results(spfResult.info);
    }
}

async function hookDataPost(stream, plugin, connection) {
    const txn = connection.transaction;

    // Step 2. DKIM
    let dkimResult;
    try {
        dkimResult = await dkimVerify(stream, {
            resolver: plugin.resolver,
            sender: txn.notes.sender,
            seal: null,
            minBitLength: plugin.cfg?.auth?.minBitLength
        });
        txn.notes.dkimResult = dkimResult;
        for (let result of dkimResult?.results || []) {
            if (result.info) {
                connection.auth_results(result.info);
            }
        }
    } catch (err) {
        txn.notes.dkimResult = { error: err };
        plugin.logerror(err, plugin, connection);
    }

    // Step 3. ARC
    let arcResult;
    if (dkimResult?.arc) {
        try {
            arcResult = await arc(dkimResult.arc, {
                resolver: plugin.resolver,
                minBitLength: plugin.cfg?.auth?.minBitLength
            });
            txn.notes.arcResult = arcResult;

            if (arcResult.info) {
                connection.auth_results(arcResult.info);
            }
        } catch (err) {
            txn.notes.arcResult = { error: err };
            plugin.logerror(err, plugin, connection);
        }
    }

    // Step 4. DMARC
    let dmarcResult;
    let spfResult = txn.notes.spfResult;
    if (dkimResult?.headerFrom) {
        try {
            dmarcResult = await dmarc({
                resolver: plugin.resolver,
                headerFrom: dkimResult.headerFrom,
                spfDomains: [].concat((spfResult?.status?.result === 'pass' && spfResult?.domain) || []),
                dkimDomains: (dkimResult.results || []).filter(r => r.status.result === 'pass').map(r => r.signingDomain),
                arcResult
            });
            txn.notes.dmarcResult = dmarcResult;

            if (dmarcResult.info) {
                connection.auth_results(dmarcResult.info);
            }
        } catch (err) {
            txn.notes.dmarcResult = { error: err };
            plugin.logerror(err, plugin, connection);
        }
    }

    // Step 5. BIMI
    let bimiResult;
    if (dmarcResult) {
        try {
            bimiResult = await bimi({
                resolver: plugin.resolver,
                dmarc: dmarcResult,
                headers: dkimResult.headers
            });
            txn.notes.bimiResult = bimiResult;

            if (bimiResult.info) {
                connection.auth_results(bimiResult.info);
            }

            txn.remove_header('bimi-location');
            txn.remove_header('bimi-indicator');
        } catch (err) {
            txn.notes.bimiResult = { error: err };
        }
    }
}

module.exports = { hookDataPost, hookMail };
