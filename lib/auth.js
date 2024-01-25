'use strict';

const { arc } = require('mailauth/lib/arc');
const { dmarc } = require('mailauth/lib/dmarc');
const { spf: checkSpf } = require('mailauth/lib/spf');
const { dkimVerify } = require('mailauth/lib/dkim/verify');
const { bimi } = require('mailauth/lib/bimi');
const libmime = require('libmime');

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

    const queueId = txn.uuid;

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

        const contentTypeHeaders = txn.header.get_all('Content-Type').map(line => libmime.parseHeaderValue(`${line}`));

        for (let result of dkimResult?.results || []) {
            if (result.info) {
                connection.auth_results(result.info);
            }

            const signingHeaders = (result.signingHeaders?.keys || '')
                .toString()
                .split(':')
                .map(e => e.toLowerCase().trim());

            plugin.loggelf({
                short_message: '[DKIM] ' + result.status?.result,
                _queue_id: queueId,
                _mail_action: 'dkim_verify',
                _dkim_info: result.info,
                _dkim_status: result.status?.result,
                _dkim_length_limited: result.canonBodyLengthLimited ? 'yes' : 'no',
                _dkim_over_sized: result.status?.overSized,
                _dkim_aligned: result.status?.aligned,
                _dkim_signing_domain: result.signingDomain,
                _dkim_selector: result.selector,
                _dkim_algo: result.algo,
                _dkim_mod_len: result.modulusLength,
                _dkim_canon_header: result.format.split('/').shift(),
                _dkim_canon_body: result.format.split('/').pop(),
                _dkim_body_size_source: result.sourceBodyLength,
                _dkim_body_size_canon: result.canonBodyLengthTotal,
                _dkim_body_size_limit: result.canonBodyLengthLimited && result.canonBodyLengthLimit,
                _dkim_signing_headers: signingHeaders.join(','),
                _dkim_signing_headers_content_type: signingHeaders.includes('content-type') ? 'yes' : 'no',
                _content_type_count: contentTypeHeaders.length,
                _content_type_boundary: contentTypeHeaders.length ? contentTypeHeaders.at(-1)?.params?.boundary?.substr(0, 20) : null
            });
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
        const passingDomains = (dkimResult.results || [])
            .filter(r => r.status.result === 'pass')
            .map(r => ({
                id: r.id,
                domain: r.signingDomain,
                aligned: r.status.aligned,
                overSized: r.status.overSized
            }));

        try {
            dmarcResult = await dmarc({
                resolver: plugin.resolver,
                headerFrom: dkimResult.headerFrom,
                spfDomains: [].concat((spfResult?.status?.result === 'pass' && spfResult?.domain) || []),
                dkimDomains: passingDomains,
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
                headers: dkimResult.headers,

                // require valid DKIM, ignore SPF
                bimiWithAlignedDkim: true
            });
            txn.notes.bimiResult = bimiResult;

            if (bimiResult.info) {
                connection.auth_results(bimiResult.info);
            }

            txn.remove_header('bimi-location');
            txn.remove_header('bimi-indicator');
        } catch (err) {
            txn.notes.bimiResult = { error: err };
            plugin.logerror(err, plugin, connection);
        }
    }
}

module.exports = { hookDataPost, hookMail };
