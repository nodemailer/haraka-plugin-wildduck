# Wild Duck plugin for Haraka

This plugin enables recipient checks for Haraka. The plugin normalizes recipient email addresses and validates these against the users table in Wild Duck database. It also checks quota usage, so if the user quota is already exceeded, then the message is rejected.

## Install

```sh
cd /path/to/local/haraka
npm install haraka-plugin-wildduck
echo "wildduck" >> config/plugins
service haraka restart
```

WildDuck plugin should be placed last in the plugins file.

### Configuration

Wild Duck plugin expects MongoDB settings to be set. By default it uses unauthenticated localhost, if you need to use a more specific settings then create your own configuration file

```sh
cp node_modules/haraka-plugin-wildduck/config/wildduck.ini config/wildduck.ini
$EDITOR config/wildduck.ini
```

### Notes

This is the only delivery plugin you need to use Haraka with Wild Duck. Make sure Haraka has no other delivery plugin enabled.

For antispam WildDuck supports Haraka Rspamd plugin. WildDuck uses Rspamd output to route messages marked as spam to the Junk mailbox.
