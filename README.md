# WildDuck plugin for Haraka

This plugin:

- enables recipient checks for Haraka. It normalizes recipient email addresses and validates these against the users table in the WildDuck database.
- checks quota usage, so if the user quota has been exceeded, the message is rejected.
- delivers messages to mongodb.

## Install

```sh
cd /path/to/local/haraka
npm install haraka-plugin-wildduck
echo "wildduck" >> config/plugins
service haraka restart
```

WildDuck plugin should be placed last in the plugins file.

### Configuration

This plugin expects MongoDB settings to be set. By default, it uses unauthenticated localhost. If you need to use more specific settings then create your own configuration file:

```sh
cp node_modules/haraka-plugin-wildduck/config/wildduck.ini config/wildduck.ini
$EDITOR config/wildduck.ini
```

### Notes

This is the only delivery plugin you need to use Haraka with WildDuck. Make sure Haraka has no other delivery plugin(s) enabled.

For antispam, WildDuck supports [Haraka's Rspamd plugin](https://www.npmjs.com/package/haraka-plugin-rspamd). WildDuck uses Rspamd output to route messages marked as spam to the Junk mailbox.

This plugin includes SPF and DKIM support. You should not enable Haraka's built-in SPF or dkim_verify plugins.

## License

European Union Public License 1.1 ([details](http://ec.europa.eu/idabc/eupl.html)) or later

> WildDuck plugin for Haraka (`haraka-plugin-wildduck`) is part of the Zone Mail Suite (ZMS). Suite of programs and modules for an efficient, fast and modern email server.