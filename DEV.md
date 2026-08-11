# Developer notes

Internal layout, build/test workflow, and design notes for `ifnsupdate`.

## Layout

```text
.
├── ifnsupdate.go              # main package: config, netlink watch, RFC 2136 UPDATE
├── ifnsupdate_test.go         # unit + mock-server integration tests
├── ifnsupdate.service         # example systemd unit
├── Makefile                   # build / test / install / uninstall
├── config.yaml.example        # sample configuration (copy to config.yaml; do not commit secrets)
├── go.mod / go.sum
├── .goreleaser.yaml           # multi-arch release packaging
├── .github/workflows/ci.yml   # push/PR: go vet + go test
├── .github/workflows/release.yml  # tag-triggered GoReleaser → GitHub Release
├── README.md                  # user-facing docs
└── DEV.md                     # this file
```

Single `main` package; no internal libraries yet. Keep the surface small unless a second binary or reusable library appears.

## Dependencies

| Module                           | Role                                            |
| -------------------------------- | ----------------------------------------------- |
| `github.com/miekg/dns`           | Build/send DNS UPDATE, TSIG                     |
| `github.com/vishvananda/netlink` | Interface lookup, address list, `AddrSubscribe` |
| `gopkg.in/yaml.v3`               | Config parsing                                  |

Run after dependency changes:

```bash
go mod tidy
```

## Build

```bash
make              # or: go build -o ifnsupdate .
make test
make vet
make clean
```

Flags (binary):

```text
-config string   path to YAML config (default "/etc/ifnsupdate/config.yaml")
-force           force a DNS UPDATE even if records already match, then exit
-delete string   delete DNS records for this name (one-shot), then exit
-type string     RR type for -delete (e.g. A, TXT); empty = all types at the name
```

### Install / packaging

```bash
sudo make install                 # PREFIX=/usr by default (binary → /usr/bin)
make install DESTDIR=/tmp/stage   # staged root for packaging
sudo make uninstall               # keeps /etc/ifnsupdate/config.yaml
make help
```

Override `PREFIX`, `BINDIR`, `SYSCONFDIR`, `UNITDIR`, `DESTDIR`, `GO`, `GOFLAGS`, `LDFLAGS` as needed. `install` does not overwrite an existing `config.yaml`.

## Test

```bash
make test
go test ./...
go test -v -count=1 ./...          # verbose, no cache
go test -run TestPerformDNSUpdate -v .
go vet ./...                       # or: make vet
```

Tests cover:

| Area                 | Examples                                                                                         |
| -------------------- | ------------------------------------------------------------------------------------------------ |
| Config load/validate | missing fields, FQDN/TTL defaults, relative names + zone, CNAME/TXT/static A, intervals, TSIG    |
| Address helpers      | `filterRecords`, CNAME target normalize, concurrency on `currentIPs`                             |
| DNS UPDATE           | mock UDP server, A+AAAA+CNAME+TXT inserts, require address per dynamic record, non-success RCODE |
| Refresh logic        | no-op when unchanged; cache only after successful update (`TestFailedUpdateAllowsRetry`)         |
| Event loop           | retry after failure; address change during retry; periodic static verify                         |
| Netlink (live)       | `getGlobalAddrs` on `lo` (expects no global addrs); eth0 used when present                       |

### Mock DNS servers in tests

`miekg/dns`’s default `MsgAcceptFunc` only accepts standard queries. UPDATE tests must accept all opcodes:

```go
server := &dns.Server{
    Net: "udp",
    MsgAcceptFunc: func(dh dns.Header) dns.MsgAcceptAction {
        return dns.MsgAccept
    },
    Handler: dns.HandlerFunc(...),
}
```

Bind with `net.ListenPacket("udp", "127.0.0.1:0")` and assign `server.PacketConn` so ports do not collide.

### Live smoke (optional)

Against a throwaway UDP mock on port 5353:

```bash
# terminal 1: any minimal UPDATE responder
# terminal 2:
./ifnsupdate -config /path/to/test.yaml
```

Point `interface` at a real iface (`eth0`, …), `dns.server` at `127.0.0.1:5353`, and use a dummy zone/records. You should see opcode UPDATE and `DNS UPDATE successful`.

Simulating address changes without root is hard (`ip addr add` needs privileges). Prefer unit tests that call `performDNSUpdate` / `refreshAndUpdate` directly.

## Code map

### Config

- `loadConfig` — read YAML
- `validateConfig` — required fields; normalize zone/name FQDNs; upper-case record types; default TTL `300` and TSIG algorithm `hmac-sha256`; parse `retry_interval` / `static_verify_interval` into `cfg.retryInterval` / `cfg.staticVerifyInterval`
- `Record.Value` — static RDATA; empty on interface-backed A/AAAA and timestamp TXT
- `Record.isStatic()` — CNAME always; TXT when `value` is set; A/AAAA when `value` is set
- `Record.isTimestamp()` — TXT with empty `value`; RDATA is `time.Now().UTC()` as RFC3339 when building the RR

### Runtime loop (`eventLoop`)

1. Resolve interface → `ifIndex`, subscribe to netlink address updates
2. `eventLoop`: initial `reconcile(force=true, scopeAll)` (query DNS, UPDATE if needed)
3. On netlink event for `ifIndex`: `reconcile` dynamic records (force full scope if a prior failure is still pending)
4. On `static_verify_interval` timer: `reconcile(force=true, scopeStatic)`
5. On failure: schedule a timer (`cfg.retryInterval`); on fire, `reconcile(force=true, scopeAll)` with **current** addresses
6. Exit on `SIGINT` / `SIGTERM`

CLI `-force` is a separate one-shot path in `main`: `initialSync(..., alwaysUpdate=true)` then exit (no netlink, no `eventLoop`).

### Record scopes

| Scope          | Records included                                                         |
| -------------- | ------------------------------------------------------------------------ |
| `scopeAll`     | Every configured record                                                  |
| `scopeDynamic` | A/AAAA without `value`, plus timestamp TXT (rides along)                 |
| `scopeStatic`  | A/AAAA with `value`, CNAME, static TXT, plus timestamp TXT (rides along) |

### Address selection

- `getGlobalAddrs(ifIndex)` lists `FAMILY_ALL`, keeps first IPv4 and first IPv6 that pass `isGlobalUnicast`
- Filters: loopback, multicast, link-local. Does **not** filter RFC1918 or IPv6 ULA (comment in source if you want public-only IPv6)

### DNS update

- `buildRR` constructs A/AAAA/CNAME/TXT presentation → `dns.NewRR`
- `performDNSUpdate(cfg, recs, v4, v6)` builds `dns.Msg` with `SetUpdate(zone)` for the given subset
- Per record: `RemoveRRset` + `Insert` (error if dynamic family missing)
- Optional `SetTsig` + `client.TsigSecret`
- Fail if `Rcode != NOERROR`
- `recordMatches` / `recordsNeedUpdate` verify each type (IP equality, CNAME target, TXT concatenated strings)
- Timestamp TXT matches if any single TXT RR exists (value not compared), so an old ISO timestamp does not force a no-op rewrite; missing timestamp still needs update

### Caching / retries

`reconcile` advances `last` only after a successful UPDATE+verify for non-static scopes (or when DNS already matches). On failure the cache is left unchanged and `eventLoop` sets `pending` and arms a retry timer (`cfg.retryInterval`, default 5m).

Each retry re-reads the interface via `readInterfaceAddrs` / `getGlobalAddrs`, so an address change during the wait is what gets published. A netlink event while `pending` forces an immediate full attempt (does not wait for the timer) and reschedules the timer if it still fails.

Static records do not use the address cache; they are checked at startup and on `cfg.staticVerifyInterval` (default 1h).

## Design choices

| Choice                                   | Rationale                                                                           |
| ---------------------------------------- | ----------------------------------------------------------------------------------- |
| Netlink subscribe vs polling             | Low latency, no busy loop; Linux-specific                                           |
| Replace RRset (delete + insert)          | Classic dynamic-update pattern; avoids multi-A accumulation                         |
| Require address for every dynamic record | Simpler UPDATE + post-update verify; operators only list families the interface has |
| Static via `value` field                 | One schema for fixed A/AAAA, CNAME, TXT without a second config section             |
| Empty TXT value = last-update timestamp  | Mirrors empty A/AAAA = from interface; dig shows when last UPDATE ran (RFC3339 UTC) |
| Separate static verify interval          | Static data does not change with netlink; still recover from zone drift             |
| Cache after success only                 | Avoid permanent silence after a single failed UPDATE                                |
| Configurable retry interval              | Operators can tune recovery from nameserver outages                                 |
| UDP + 10s timeout                        | Matches common UPDATE deployment; TCP not implemented                               |

## Style

- Prefer the Go standard `log/slog` package (`slog.Info` / `slog.Error` with structured attributes)
- Keep validation and DNS construction pure enough to unit-test without root
- Do not log TSIG secrets
- Match existing naming: `Config`, `DNSConfig`, `Record`, `performDNSUpdate`, …

## Releases (GoReleaser)

Releases are automated with [GoReleaser](https://goreleaser.com/). Pushing a semver tag `v*` runs `.github/workflows/release.yml`, which builds Linux amd64/arm64 archives, checksums, changelog, and uploads a GitHub Release.

### Where artifacts live

| Location                   | Layout                                                                                                                    |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Local `dist/` (gitignored) | GoReleaser working dir: per-target binaries, then `.tar.gz` + `checksums.txt`                                             |
| Inside each `.tar.gz`      | Wrapped in a directory, e.g. `ifnsupdate_0.1.0_linux_amd64/{ifnsupdate,README.md,config.yaml.example,ifnsupdate.service}` |
| GitHub Release assets      | **Flat** list of archives + `checksums.txt` (no subfolders on the release page)                                           |

Do **not** commit binaries under the repo root or `dist/`. Only publish via GitHub Releases (or `go install`).

### Local dry-run (no publish)

```bash
# Requires goreleaser: https://goreleaser.com/install/
goreleaser check
goreleaser release --snapshot --clean   # writes under ./dist/
```

### Publish a release

1. Clean tree on the commit you want to ship; `go test ./...` and `go vet ./...`
2. Manual lab run with TSIG if possible
3. Tag and push:

```bash
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

4. GitHub Actions runs GoReleaser and creates the release

Optional laptop publish (needs clean git + `GITHUB_TOKEN` with `repo`/`contents: write`):

```bash
goreleaser release --clean
```

Prerelease tags such as `v1.0.0-rc.1` are marked as prereleases (`prerelease: auto` in `.goreleaser.yaml`).

### Checklist

1. `go test ./...` and `go vet ./...`
2. Manual run against a lab nameserver with TSIG
3. Tag `vX.Y.Z` on the intended commit and push the tag
4. Confirm the Actions run and the GitHub Release assets look right
5. Consumers can `go install github.com/abundo/ifnsupdate@vX.Y.Z` or download archives from the release
