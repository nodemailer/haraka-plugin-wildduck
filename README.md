# Wild Duck plugin for Haraka

This plugin enables recipient checks for Haraka.

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
$EDITOR config/template.ini
```
