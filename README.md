# WildDuck plugin for Haraka

This plugin enables recipient checks for Haraka. The plugin normalizes recipient email addresses and validates these against the users table in the WildDuck database. It also checks quota usage, so if the user quota has already been exceeded, the message is rejected.

## Install

```sh
cd /path/to/local/haraka
npm install haraka-plugin-wildduck
echo "wildduck" >> config/plugins
service haraka restart
```

WildDuck plugin should be placed last in the plugins file.

### Configuration

WildDuck plugin expects MongoDB settings to be set. By default, it uses unauthenticated localhost. If you need to use more specific settings then create your own configuration file

```sh
cp node_modules/haraka-plugin-wildduck/config/wildduck.ini config/wildduck.ini
$EDITOR config/wildduck.ini
```

### Notes

This is the only delivery plugin you need to use Haraka with WildDuck. Make sure Haraka has no other delivery plugin enabled.

For antispam, WildDuck supports Haraka Rspamd plugin. WildDuck uses Rspamd output to route messages marked as spam to the Junk mailbox.
