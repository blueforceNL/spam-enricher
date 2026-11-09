# Spam Enricher

The spam enricher performs strictly regulated, continuous enrichment for observables extracted by local email analysis. Some threat intelligence
sources provide limited quota per day, especially free or cheap ones. These sources are relevant and we would like to use the returned information
while also respecting quota and frequency of API requests. Therefore, the `spam-enricher` performs the enrichment, after which our own threat
intelligence platform can request enrichment data without limitation from the spam trap server.

## Installation

Copy the contents of the repository inside `/opt/spam-enricher/` except the `etc` directory. This contains an example configuration file and systemd
service descriptor. First create the configuration file from the example.

```bash
mkdir /etc/spam-enricher
cp /opt/spam-enricher/etc/enricher.conf.sample /etc/spam-enricher/enricher.conf
```

Set the required config parameters as described in the configuration section. Next, create the systemd service as follows, enable it and start the enricher.

```bash
cp /opt/spam-enricher/etc/spam-enricher.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable spam-enricher
systemctl start spam-enricher
```

Finally, create a symbolic link to `enricher-queue-ctl.sh` in a directory included in `$PATH`.

```bash
chmod +x /opt/spam-enricher/enricher-queue-ctl.sh
ln -s /opt/spam-enricher/enricher-queue-ctl.sh /usr/local/bin/enricher-queue-ctl
```

## Configuration

The configuration file looks as follows. It contains a several basic parameters to access the database, and a few to tune the inner workings of the enricher.

| Parameter          | Description                                                                                                                                                        |
|--------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ttl_days           | The number of days to retain an enrichment result in cache before redoing it.                                                                                      |
| queue_block_size   | The number of scheduled IP observables to read from the queue and process simultaneously. Increasing this parameter reduces the number of queries to the database. |
| max_inactive_queue | The maximum size of scheduled entries allowed to be retained in the inactive queue: a separate queue to keep scheduled observables close for when quota are reset. |

The other sections describe enrichment modules. The `names` field under the section `MODULES` describes which enrichment modules are to be loaded by the enricher. Every module has its
own parameters, a combination of mandatory ones and optional, module-specific parameters.

| Parameter          | Description                                                                                                                             |
|--------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| enabled            | Specifies whether the given module is enabled or not.                                                                                   |
| supported_types    | Types of observable supported for enrichment. For example, ip or domain.                                                                |
| quota              | The daily quota of the external enrichment API for the given source. The enricher will respect this daily quota.                        |
| delay              | Delay in seconds between every request performend to the external enrichment API. The enricher will respect the frequenecy of requests. |
| api_key            | Optional parameter that specifies the API key used for external enrichment requests for a given API.                                    |

## Usage

### Spam Enricher

The help summary can be requested using the `-h` switch.

```
usage: spam_enricher.py [-h] [-l] [indicator]

Spam enricher

positional arguments:
  indicator

options:
  -h, --help  show this help message and exit
  -l          List enabled enricher modules
```

To list all configured and enabled enricher modules, use the `-l` switch.

```
Listing configured listeners...
Listener: vpnapi, enabled: True, supported_types: ['ip'], quota: 900, delay: 5
Listener: ip2proxy, enabled: True, supported_types: ['ip'], quota: 2147483647, delay: 0
```

The `spam-enricher` is designed to run as a service under systemd. when run without arguments, it runs as normal.

```bash
systemctl start spam-enricher
```

### Enricher Queue Controller

The queue controller, dubbed `enricher-queue-ctl`, can be used to manage the queue in which observables are inserted for enrichment. You can query the current status
of the active and inactive queues using the `-q` switch.

```
INFO: 0 entries in the queue covering 0 unique indicators.
INFO: 59377 entries currently inactive for 57476 unique indicators. (maximum number configured = 65536)
INFO: Enricher states currently in database.
INFO: vpnapi has 0 remaining quota. Last request at: 2026-11-09 01:17:07 (status code = 200). Configured quota = 900, delay = 5, last quota reset = 2026-11-09 00:00:00.
INFO: ipintel (disabled) has 500 remaining quota. Last request at: 2024-10-24 02:59:04 (status code = 200). Configured quota = 500, delay = 60, last quota reset = 2024-11-25 00:00:02.
INFO: ip2proxy has 2147465022 remaining quota. Last request at: 2026-11-09 09:17:48 (status code = 0). Configured quota = 2147483647, delay = 0, last quota reset = 2026-11-09 00:00:02.
```

Furthermore, the `-c` switch can be used to clear the queue and start over, the `-a` switch to add a new observable to the queue and the `-r` switch to remove one. When adding an
observable to the queue, the `-e` switch can be used to specify a specific enricher module by name. Two troubleshooting options are implemented, namely `-d` to deduplicate the queue
instantly. This can be quite slow when the number of entries is large. Finally, the `-i` switch can be used to force inactive entries back to the active queue. Should not be needed
for anything else than debugging.
