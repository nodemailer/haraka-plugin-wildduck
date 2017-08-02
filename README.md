# Wild Duck plugin for Haraka

This plugin enables recipient checks for Haraka. The plugin normalizes recipient email addresses and validates these against the users table in Wild Duck database. It also checks quota usage, so if the user quota is already exceeded, then the message is rejected.

## Install

```sh
cd /path/to/local/haraka
npm install haraka-plugin-wildduck
echo "wildduck" >> config/plugins
service haraka restart
```

Additionally you should enable `queue/lmtp` plugin as the Wild Duck plugin only checks recipient info but does not do the actual delivery.

### Configuration

Wild Duck plugin expects MongoDB settings to be set. By default it uses unauthenticated localhost, if you need to use a more specific settings then create your own configuration file

```sh
cp node_modules/haraka-plugin-wildduck/config/wildduck.ini config/wildduck.ini
$EDITOR config/wildduck.ini
```

### Notes

Minimally you would need this plugin and [queue/lmtp](http://haraka.github.io/manual/plugins/queue/lmtp.html) plugin to use Haraka with Wild Duck.

If you use a antispam plugin as well, then messages with headers "X-RSpamd-Spam: Yes" or "X-Spam-Status: Yes" are delivered to the Junk folder automatically. Which header is preferred can be set in Wild Duck config file (by default X-RSpamd-Spamd is used).
