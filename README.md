# ifnsupdate

Linux client that keeps DNS records in sync with a network interface’s current IP addresses, and can also maintain static records (fixed A/AAAA, CNAME, TXT) via the same RFC 2136 UPDATE path.

When the interface gains, loses, or changes a global IPv4/IPv6 address, the client sends an [RFC 2136](https://datatracker.ietf.org/doc/html/rfc2136) DNS `UPDATE` to your authoritative nameserver (optionally authenticated with TSIG). Think of it as **nsupdate for a network interface**.

## Features

- Watches a single interface via netlink address events
- Updates interface-backed `A` / `AAAA` records from the interface’s global unicast addresses
- Maintains **static** records independent of the interface: fixed `A`/`AAAA`, `CNAME`, `TXT`
- Optional **last-update timestamp** `TXT` (no `value`): written as ISO 8601 / RFC3339 UTC whenever an UPDATE runs
- Optional TSIG authentication (`hmac-sha256` and other common algorithms)
- Replace semantics: remove the existing RRset, then insert the new record
- Configurable retry after failed updates; periodic re-verify of static records
- Always verifies all configured records (dynamic + static) at startup
- Default one-shot sync; continuous monitoring only with `-daemon`
- `-force` CLI flag for a one-shot forced DNS UPDATE (then exit)

## Requirements

- **Linux** (uses [netlink](https://github.com/vishvananda/netlink))
- **Go 1.22+** to build (module targets a recent Go toolchain)
- A nameserver that accepts RFC 2136 dynamic updates for your zone (e.g. BIND, PowerDNS, Knot)
- Permission to open a netlink route socket (normally works as a regular user for address monitoring)

## Install

### Quick start

GitHub Releases (tag `v*`) publish Linux **amd64** and **arm64** archives via [GoReleaser](https://goreleaser.com/), with `checksums.txt`. Each archive includes the binary, `config.yaml.example`, and `ifnsupdate.service`.

**1. Download and install the binary**

```bash
# Example: tag v0.1.0 on amd64 (archive name uses the version without the leading v)
curl -fsSL -o ifnsupdate.tar.gz \
  https://github.com/abundo/ifnsupdate/releases/download/v0.1.0/ifnsupdate_0.1.0_linux_amd64.tar.gz
tar -xzf ifnsupdate.tar.gz
# extracts into ifnsupdate_0.1.0_linux_amd64/
sudo install -m 755 ifnsupdate_0.1.0_linux_amd64/ifnsupdate /usr/bin/ifnsupdate
```

**2. Install and edit the config**

```bash
sudo install -d -m 755 /etc/ifnsupdate
sudo install -m 600 ifnsupdate_0.1.0_linux_amd64/config.yaml.example /etc/ifnsupdate/config.yaml
sudoedit /etc/ifnsupdate/config.yaml
```

Set at least `interface`, `dns.server`, `dns.zone`, records, and (if required) `dns.tsig`. Protect the file if it contains a TSIG secret (`0600` or `0640`).

**3. Install the systemd service**

```bash
sudo install -m 644 ifnsupdate_0.1.0_linux_amd64/ifnsupdate.service \
  /etc/systemd/system/ifnsupdate.service
sudo systemctl daemon-reload
sudo systemctl enable --now ifnsupdate
```

The unit runs `/usr/bin/ifnsupdate -daemon -config /etc/ifnsupdate/config.yaml`. Optional: uncomment `User=` / `Group=` in the unit and create a system user (`useradd --system --no-create-home --shell /usr/sbin/nologin ifnsupdate`); keep the config readable by that user (e.g. `root:ifnsupdate` mode `0640`).

### From source

```bash
git clone https://github.com/abundo/ifnsupdate.git
cd ifnsupdate
make
# or: mkdir -p bin && go build -o bin/ifnsupdate .
```

Install the binary, example config, and systemd unit (default prefix `/usr`):

```bash
sudo make install
# edit /etc/ifnsupdate/config.yaml
sudo systemctl daemon-reload
sudo systemctl enable --now ifnsupdate
```

`make install` places:

| Path                                     | Notes                                    |
| ---------------------------------------- | ---------------------------------------- |
| `/usr/bin/ifnsupdate`                    | binary (`PREFIX` / `BINDIR` overridable) |
| `/etc/ifnsupdate/config.yaml`            | created only if missing (mode `0600`)    |
| `/etc/ifnsupdate/config.yaml.example`    | always refreshed from the repo example   |
| `/etc/systemd/system/ifnsupdate.service` | unit file                                |

Override paths with `make install PREFIX=/usr/local` or staged packaging via `DESTDIR=...`.

Or install into your `GOBIN`:

```bash
go install github.com/abundo/ifnsupdate@latest
# or a specific release tag:
go install github.com/abundo/ifnsupdate@v0.1.0
```

See [DEV.md](DEV.md) for how maintainers cut a release.

## Configuration

Copy and edit the example:

```bash
cp config.yaml.example config.yaml
# or: cp config.yaml.example config.yaml.local && ./bin/ifnsupdate -config config.yaml.local
```

Example `config.yaml.example`:

```yaml
interface: eth0

retry_interval: 5m
static_verify_interval: 1h

dns:
  server: "ns1.example.com:53"
  zone: "example.com."
  tsig:
    name: "ifnsupdate-key.example.com."
    secret: "BASE64SECRET==" # base64-encoded shared secret
    algorithm: hmac-sha256

records:
  # Interface-backed (no value) → myhost.example.com. A/AAAA from eth0
  - name: myhost
    type: A
    ttl: 300
  - name: myhost
    type: AAAA
    ttl: 300

  # Static A (fixed address)
  - name: fixed
    type: A
    value: "192.0.2.10"
    ttl: 300

  # CNAME alias → myhost.example.com.
  - name: www
    type: CNAME
    value: myhost
    ttl: 300

  # TXT (static)
  - name: myhost
    type: TXT
    value: "v=spf1 -all"
    ttl: 300

  # Last-update timestamp (no value → ISO 8601 UTC on each UPDATE)
  - name: myhost-updated
    type: TXT
    ttl: 300
```

### Fields

| Field                    | Required  | Description                                                                                       |
| ------------------------ | --------- | ------------------------------------------------------------------------------------------------- |
| `interface`              | yes       | Linux interface name to monitor (`eth0`, `wlan0`, `wg0`, …)                                       |
| `retry_interval`         | no        | Wait after a failed DNS update before retrying (Go duration, default `5m`)                        |
| `static_verify_interval` | no        | How often to re-check static records after start (Go duration, default `1h`)                      |
| `dns.server`             | yes       | Nameserver host:port for UPDATE queries (UDP)                                                     |
| `dns.zone`               | yes       | Zone apex for the UPDATE (trailing `.` added if missing)                                          |
| `dns.tsig`               | no        | TSIG credentials; omit only if the server allows unauthenticated updates                          |
| `dns.tsig.name`          | with tsig | Key name (FQDN; trailing `.` added if missing)                                                    |
| `dns.tsig.secret`        | with tsig | Base64-encoded secret                                                                             |
| `dns.tsig.algorithm`     | no        | Default `hmac-sha256`. Also: `hmac-md5`, `hmac-sha1`, `hmac-sha224`, `hmac-sha384`, `hmac-sha512` |
| `records[].name`         | yes       | Name to maintain: relative to `dns.zone` (`myhost`), `@` for the apex, or an FQDN **in** the zone |
| `records[].type`         | yes       | `A`, `AAAA`, `CNAME`, or `TXT`                                                                    |
| `records[].value`        | see below | Static RDATA (required for CNAME; optional for A/AAAA/TXT — empty TXT = last-update timestamp)    |
| `records[].ttl`          | no        | TTL in seconds (default `300`)                                                                    |

Trailing dots on zone and TSIG name are normalized automatically. Durations use Go syntax (`30s`, `5m`, `1h`, …).

### Record kinds

| Type / config                    | Source of data                          | When updated                                    |
| -------------------------------- | --------------------------------------- | ----------------------------------------------- |
| `A` / `AAAA` **without** `value` | First global address on `interface`     | Startup; interface address change; failed-retry |
| `A` / `AAAA` **with** `value`    | Fixed IP in config                      | Startup; every `static_verify_interval`         |
| `CNAME` (requires `value`)       | Target name (relative or absolute FQDN) | Startup; every `static_verify_interval`         |
| `TXT` **with** `value`           | Literal string                          | Startup; every `static_verify_interval`         |
| `TXT` **without** `value`        | Current UTC time (RFC3339 / ISO 8601)   | Written whenever any UPDATE runs (rides along)  |

A timestamp `TXT` is only rewritten when something else needs fixing (or the TXT is missing). If the zone already has a single TXT at that name, it is left alone so `dig` shows the real last-update time, not “now”.

**Record names** are resolved against `dns.zone` at load time:

| Config value                                 | Resolved name (zone `example.com.`) |
| -------------------------------------------- | ----------------------------------- |
| `myhost`                                     | `myhost.example.com.`               |
| `vpn.myhost`                                 | `vpn.myhost.example.com.`           |
| `myhost.example.com` / `myhost.example.com.` | `myhost.example.com.`               |
| `@`                                          | `example.com.` (zone apex)          |
| `other.org.`                                 | **error** — not in zone             |

**CNAME targets** (`value`): relative names are resolved like record names (zone appended). Absolute names (trailing `.`) are kept as-is and may point outside the zone (e.g. `cdn.other.org.`).

Absolute owner names (trailing `.`) outside the zone are rejected.

## Usage

```bash
./bin/ifnsupdate                          # one-shot sync using /etc/ifnsupdate/config.yaml
./bin/ifnsupdate -config config.yaml      # one-shot sync (dev config)
./bin/ifnsupdate -daemon -config config.yaml  # continuous monitor (systemd uses this)
./bin/ifnsupdate -config config.yaml -force   # one-shot: force UPDATE, then exit
./bin/ifnsupdate -delete myhost                 # delete all RRsets at myhost.<zone>
./bin/ifnsupdate -delete myhost -type TXT       # delete only TXT at that name
```

| Flag      | Default                       | Description                                                                                                                                                               |
| --------- | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-config` | `/etc/ifnsupdate/config.yaml` | Path to YAML configuration file                                                                                                                                           |
| `-daemon` | off                           | Continuous mode: monitor netlink address changes and re-verify static records until stopped. Required for the event loop. Mutually exclusive with `-force` and `-delete`. |
| `-force`  | off                           | Interactive one-shot: always send a DNS UPDATE even if records already match, then exit (refreshes any last-update timestamp `TXT`)                                       |
| `-delete` | (empty)                       | One-shot: delete DNS records for this name (relative or FQDN in zone), then exit. Uses `dns.*` from the config only. Mutually exclusive with `-force` and `-daemon`.      |
| `-type`   | (empty)                       | With `-delete`: RR type to remove (`A`, `AAAA`, `TXT`, …). If omitted, all RRsets at the name are deleted.                                                                |

`-config` defaults to `/etc/ifnsupdate/config.yaml`. For local development, copy `config.yaml.example` and pass `-config` explicitly.

**Default mode** (one-shot): load config, verify all configured records, send a DNS UPDATE only if needed, then exit. Does not subscribe to netlink or run the monitor loop.

**Daemon mode** (`-daemon`): on start the client:

1. Loads and validates the config
2. Resolves the interface and reads current global addresses
3. Verifies **all** configured records (dynamic + static) and sends a DNS UPDATE if needed
4. Listens for netlink address changes until `SIGINT` / `SIGTERM`
5. Re-verifies static records every `static_verify_interval`
6. On UPDATE/verify failure, retries every `retry_interval`

**Force mode** (`-force`): load config, force a DNS UPDATE for all records (even when already correct), then exit. Does not subscribe to netlink or run the monitor loop.

**Delete mode** (`-delete`): load config DNS settings (server, zone, TSIG), send a single RFC 2136 UPDATE that removes the named records, then exit. Name resolution matches config record names (relative names get `dns.zone` appended). With `-type`, only that RRset is removed; without `-type`, every RRset at the name is removed. Does not require `interface` or `records` in the config.

Example log output (`-daemon`):

```text
monitoring interface eth0 (index 3)
retry interval interval=5m0s
static record verify interval interval=1h0m0s
IPv4 changed: <nil> → 203.0.113.10
IPv6 changed: <nil> → 2001:db8::10
will update name=myhost.example.com. type=A rdata=203.0.113.10
will update name=myhost.example.com. type=AAAA rdata=2001:db8::10
will update name=www.example.com. type=CNAME rdata=myhost.example.com.
DNS UPDATE successful
listening for IP address changes (Ctrl+C to stop)...
```

### systemd

See [Install](#install) for placing the binary, config, and unit file. After editing `/etc/ifnsupdate/config.yaml`:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ifnsupdate
sudo systemctl status ifnsupdate
```

The example unit is [`ifnsupdate.service`](ifnsupdate.service). Protect `config.yaml` (mode `0600` or `0640`) if it contains a TSIG secret.

## How it works

```text
  interface (netlink)          config static RRs
        │                              │
        ▼                              ▼
  pick first global IPv4 / IPv6   fixed value / CNAME / TXT
        │                              │
        └──────────┬───────────────────┘
                   ▼
         compare to nameserver
                   │ needs fix?
                   ▼
  DNS UPDATE (zone)  ──UDP──►  nameserver:53
    - delete RRset
    - insert new RR(s)
    - optional timestamp TXT (RFC3339 UTC)
```

- **Global unicast only (dynamic A/AAAA):** loopback, multicast, and link-local addresses are ignored. Private IPv4 (`10/8`, `192.168/16`, …) and IPv6 ULA (`fd00::/8`) are currently **included**, which is useful on LANs and VPN interfaces.
- **One address per family:** if the interface has multiple global addresses of the same family, the first one returned by netlink is used.
- **Dynamic records must be publishable:** if you configure an interface-backed `AAAA` but the interface has no global IPv6, the update fails (only list families the interface actually has). Static A/AAAA/CNAME/TXT do not depend on the interface.
- **Failed updates are retried:** after a DNS UPDATE (or post-update verify) failure, ifnsupdate retries every **`retry_interval`** (default 5 minutes), re-reading the interface each time. An address change is applied immediately even while a retry is pending.
- **Static re-verify:** static records are checked at startup and then every **`static_verify_interval`** (default 1 hour). Address changes only re-check interface-backed A/AAAA.

## Nameserver setup (sketch)

You need an update policy that allows your TSIG key to change the target names and types. BIND example:

```bind
key "ifnsupdate-key.example.com." {
    algorithm hmac-sha256;
    secret "BASE64SECRET==";
};

zone "example.com" {
    type master;
    file "example.com.zone";
    update-policy {
        grant ifnsupdate-key.example.com. name myhost.example.com. A AAAA TXT;
        grant ifnsupdate-key.example.com. name www.example.com. CNAME;
        grant ifnsupdate-key.example.com. name fixed.example.com. A;
    };
};
```

Exact syntax varies by server; ensure the key name, algorithm, and secret match `config.yaml`. Note that a name with a CNAME generally cannot hold other RR types at the same owner name.

## Limitations

- Linux only (netlink).
- Address disappearance does not remove a dynamic DNS RRset (only replace when a new address is present). Static records are re-asserted on the static verify interval.
- UDP only for the DNS exchange (10s timeout).

## License

See the repository for license terms.
