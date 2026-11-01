# AGENTS.md

Guidance for anyone (human or AI agent) changing this repository: what the
project is, the decisions behind it, and the rules we've agreed to work by.
Read it before making changes, and update it in the same commit when a
decision here changes.

## What this is

A spare-time project. `utr-monitor.py` polls a **UniFi Travel Router (UTR)**
over SSH and serves a local dashboard (system load, network, Teleport VPN,
Wi-Fi, clients, router events). `utr-probe.py` is a read-only discovery tool
that reports what a router's firmware exposes. Both are single-file Python
scripts run from a local virtualenv on the owner's Mac.

| Path | What it is |
|---|---|
| `utr-monitor.py` | Collector, parsers, SQLite store, web server and the inline dashboard page (`PAGE`) |
| `utr-probe.py` | Read-only discovery report (reuses `SSHRunner` and the password helpers from the monitor) |
| `tests/` | pytest suite; `tests/helpers.py` holds fictional router output in real firmware shapes |
| `docs/` | Screenshots, generated from `--demo` only |
| `pyproject.toml` | pytest and coverage configuration (90% coverage gate) |
| `requirements*.txt` | Runtime and development dependencies |
| `LICENSE` | MIT licence, copyright Gareth Woolridge |

## Working agreements

### Git

- Commits use the repo-local identity **Gareth Woolridge
  &lt;gareth@woolridge.org.uk&gt;** (already set in `.git/config`). This is a
  personal project; never use a work identity.
- One commit per feature or fix. Imperative subject line; the body explains
  *why* and any behaviour a user would notice.
- Agent-authored commits end with the agent's `Co-Authored-By` trailer.
- There's no remote. Don't push, add remotes or rewrite pushed history
  without being asked.
- Never commit data from the real network: databases, probe reports,
  `--once` JSON, `.DS_Store`, local archives (e.g. `utr-monitor.tar`) or
  the virtualenv. `.gitignore` covers the known ones; check `git status`
  before committing.

### Router safety

- **Read-only on the router.** Only run commands that read state. Never
  change configuration, restart services, reboot, or toggle Teleport or any
  other VPN; switching the VPN for a test is the owner's decision.
- Try a new router command with `utr-probe.py` (add it to `PROBES`) before
  the monitor depends on it.
- Keep polling cheap. The router has a 4-core ARM CPU idling at ~27%. The
  detail poll's cost is shown in the header (`detail N ms`), and the monitor's
  own CPU appears as the "This monitor" group. It should stay under ~1% of
  CPU.

### Credentials and privacy

- The SSH password is never logged, printed or written to disk by the
  scripts. It's saved only to the OS keychain via the optional `keyring`
  package, per `user@host` under the service `utr-monitor`.
- It's **stored encrypted, not hashed**: SSH needs the real password each
  time, so a one-way hash can't log in. `--password` and `$UTR_PASSWORD`
  are never saved. `--forget-password` and the README cover resetting it.
- Screenshots, test fixtures and examples use fictional data (`--demo` or
  `tests/helpers.py`). No real SSIDs, MACs, IPs, site names or hostnames in
  the repo.
- Probe reports redact lines that look like secrets (`key`, `psk`,
  `pass*`, `secret`, `token`, `private`). Redaction errs towards removing
  too much.

### Testing

- `pip install -r requirements-dev.txt`, then `pytest`. The suite enforces
  **at least 90% coverage** (branches included) of both scripts. Run it
  before every commit.
- New parsing of router output gets a test using fictional data shaped like
  the real firmware's output. Add to `tests/helpers.py` rather than pasting
  real output.
- The page's JavaScript runs under Node in `tests/test_page.py`, with a
  minimal fake DOM, against hostile router strings. Any new place that
  renders router-provided text must go through `esc()`, or that test fails.
  These tests are skipped if `node` isn't installed.
- For UI changes, also check by eye in `--demo`: both themes, and phone
  width (390px) with no horizontal scroll. Regenerate `docs/` screenshots
  from `--demo` when the UI changes noticeably.

### Documentation and writing

- README changes go in the same commit as the feature or flag they describe.
- British English in docs and UI copy ("utilisation", "colour").
- UI copy is plain and specific: say what a number is ("% of the whole CPU,
  all cores"), and label estimates as estimates.

## Code style

- **Single-file scripts, no build step.** Runtime dependencies are the
  standard library and `paramiko`, plus optional `keyring`. No web
  framework, no bundler, no CDN. The dashboard is one inline HTML/CSS/JS
  string (`PAGE`).
- **Python 3.8+.** Module-level `parse_*` functions are pure: text in,
  plain dicts out. State and deltas between polls live in `Collector`.
- **Never let unexpected router output raise.** Parse defensively, field by
  field: use `_num`, `_sat` and `_json`, skip malformed lines, and let each
  panel degrade on its own. A failing detail poll must not stop the fast
  poll.
- Log with the module `log`. `print` is only for CLI output (`--once`,
  `--forget-password`, the probe's progress).
- **JavaScript:** compact vanilla JS, `$()` for elements. All
  router-derived strings go through `esc()`. Colours are CSS variables that
  charts read at draw time, so themes apply to charts too.
- **CSS:** tokens on `:root`. Classic follows the system light/dark
  setting; "UniFi style" (`data-skin=unifi`) is always dark. No external
  fonts or assets, so the page works offline on the travel router's own LAN.
- **Browser storage** holds only per-viewer preferences (theme, CPU
  breakdown open/closed), always in `try/catch`. Anything that must persist
  goes in SQLite on the server side.

## Design decisions

### Target firmware

Written against UTR firmware **6.6.122** (LEDE 17.01, IPQ40xx, 4 × Cortex-A7,
~250 MB RAM, BusyBox). Findings from probing that the code relies on:

- SSH user `ui` gets a BusyBox shell. Exec channels work, and `/proc` is
  readable.
- Interfaces:
  - `eth0`: WAN port
  - `eth1`: LAN port
  - `ath0`–`ath3`, `ath6`, `ath7`: access-point VAPs
  - `ath4` / `ath5`: 2.4 / 5 GHz Wi-Fi uplinks (`wireless-bridge`)
  - `usb0`: USB tether
  - `wg0`: Teleport (WireGuard)
  - `br-lan`: LAN bridge
  - `wifi0`/`wifi1`, `soc*`, `ifb*`, `sit0`, `miireg`: plumbing, hidden
- `mca-dump` (UniFi's device status JSON) is the richest source: uplink,
  portal detection, LLDP, VAPs with per-client stats, radio utilisation and
  scan tables.
- `hostapd_cli` reports client signal as 0 on this driver, so per-client
  signal comes from `mca-dump`.
- No `logread`, `uci` or `iwinfo`. Syslog is in `/var/log/messages`, and
  structured events are in `/var/log/utr-runtime-events.log`. `brctl` is
  present.
- The `element-…` SSIDs are built in, not user-configured.

### Transport

- `SSHRunner` tries an exec channel first and falls back to one
  interactive shell if the restricted shell refuses exec. In shell mode,
  output is framed by a marker echoed as `"__UTR_""DONE_n__"`. The quotes
  split the marker in the echoed command line, so only the real output
  contains it.
- Host keys are auto-accepted, because travel routers are reset and
  re-adopted often. On failure the session is closed and retried with
  backoff (2 s doubling to 60 s).
- Startup checks the login before serving. A rejected saved password is
  removed and the user is asked again (3 attempts). An unreachable router
  doesn't block startup.

### Two polls

- **Fast poll** (`--interval`, default 2 s): one compound command reading
  `/proc/stat`, `/proc/meminfo`, `/proc/net/dev` and `/proc/loadavg`. If
  `/proc` isn't readable it falls back to `top -bn1` + `ifconfig`. CPU and
  throughput are counter deltas, so the first poll only primes the counters.
- **Detail poll** (`--detail-interval`, default 10 s, minimum 5, `0` turns it
  off): `mca-dump`, the Teleport status JSON, `wg show` (handshakes and
  transfer only, never keys), multi-WAN ping files, DHCP leases, ARP, the
  event log, routes, addresses, `/proc/net/wireless`, `brctl showmacs`, and
  a process snapshot.
  - Sections are separated by `@@UTR_SECTION@@`, and the process snapshot
    follows `@@UTR_PROCS@@`.
  - It takes about 1.1 s on the router.

### Interpreting the data

- **Interface names** come from `mca-dump`:
  - `uplink` gives the active WAN, and `portal_detect` lists the WAN
    candidates.
  - VAP `usage` separates access points (`user`) from uplinks
    (`wireless-bridge`), and `lan_table` lists the LAN members.
  - Without `mca-dump`, the active WAN falls back to the lowest-metric
    default route.
- **A WAN is connected** only with a non-link-local IPv4 address. An
  unassociated uplink holds `169.254.x`. Uplink signal is reported only for
  an associated uplink, and a `/proc/net/wireless` level ≤ −95 dBm (the
  noise floor) falls back to the scan table.
- **Latency** comes from the multi-WAN daemon's
  `/var/run/unifi_mwan.status.ping.<iface>`, so the monitor sends no pings of
  its own. A connected WAN with no file is failing its health checks and
  shows as "no reply".
- **Events:**
  - **Time** is boot time + the event's `monotonic` counter, because `ts`
    can be a pre-NTP clock.
  - **ID** is `sha1(boot_id + line)`, so re-reading the log tail never
    duplicates an event.
  - **Reset** clears stored events but keeps the seen-set, so old log lines
    don't come back.
- **Clients:**
  - Wi-Fi clients come from VAP station tables, with names and IPs from DHCP
    leases when `mca-dump` lacks them.
  - **Wired clients** are br-lan ARP entries whose MAC the bridge FDB saw on
    a non-Wi-Fi port within 300 s. ARP alone isn't enough, because entries
    linger after a Wi-Fi client leaves. Without `brctl`, it falls back to
    ARP (documented limitation).
  - The router doesn't count traffic per wired device, so **wired traffic is
    the LAN port's counters**: exact with one device, labelled "shared"
    with several.

### CPU accounting and the Teleport cost estimate

- Each detail poll diffs every `/proc/<pid>/stat`:
  - **Live processes** count their own utime+stime.
  - **Children that exited** are credited to their parent's cutime/cstime,
    minus whatever was already counted while they were visible, so nothing
    is counted twice.
  - **Processes started during the interval** count their own time only;
    their reaped children surface through their parent later.
  - **Processes seen for the first time that started earlier** are baseline
    only.
- **Groups:**
  - **Teleport:** `teleport-client`, `wireguard-client`, `openvpn-client`,
    the Teleport `dnsmasq` and `wg-crypt-*`.
  - **Teleport status polling:** live commands mentioning teleport, plus
    the reaped children of parents seen spawning them (e.g. the LCD
    daemon). This is an estimate.
  - **This monitor:** the dropbear session that is the parent of the poll's
    `$$`.
  - **Kernel threads:** children of `kthreadd`.
  - **Other** and **Interrupts & short-lived:** "Interrupts & short-lived"
    is the CPU time not attributed to any process.
- All percentages are of the **whole CPU (all cores)**, matching the CPU
  chart.
- **The Teleport cost** is a least-squares fit of kernel CPU (system +
  softirq) against tunnel throughput:
  - WireGuard encrypts in kernel workers and softirq, which normal routing
    shares, so its cost can't be read off a process.
  - A second term for non-VPN traffic is fitted only when it varies
    independently (|correlation| < 0.9).
  - The intercept is the router's baseline, **not** the idle tunnel's cost.
  - "VPN up vs down" compares idle periods (WAN under 1 Mb/s).
  - "Ceiling" projects 100% CPU from the idle baseline.
- **Reference measurements** (October 2026, firmware 6.6.122, UCG-Fiber at
  the far end over Cat6):
  - Teleport costs ~4.6% of CPU per 10 Mb/s, against ~1.4% for plain
    routing.
  - The ceiling is ~160–175 Mb/s through Teleport, against ~520–570 Mb/s
    without it.
  - An idle tunnel costs nothing measurable, and the idle baseline is ~27%.

### Storage

- SQLite in WAL mode, with `samples`, `details` and `events` tables. One
  file per router, `utr-monitor-<host>.db`, in the working directory.
- **History is kept for 30 days**, then deleted. A travel router rarely
  stays up longer than a few days to a week, so 30 days covers several
  trips without the file growing unbounded. Pruning runs at startup and
  every 10 minutes. `--retention-days` overrides it, but 30 days is the
  supported default.
- Data is stored at full resolution for the whole 30 days. Downsampling is
  future work (see below).
- On startup the last `--history` points are reloaded into the charts, and
  lines break across gaps rather than joining them up.
- `--demo` never writes to a database unless `--db` is given.
- Current state (the tables) isn't stored, because it refreshes within one
  detail poll.

### Web server and page

- Binds to `127.0.0.1` by default, with no authentication. `POST
  /api/reset` requires the header `X-UTR-Reset: 1`, which other websites
  can't send without a CORS preflight that the server never approves.
- `/api/data` takes cursors (`since`, `dsince`, `eseq`) so each poll sends
  only new points. CSV export streams from SQLite in chunks.
- Layout:
  - **Summary tiles**
  - **System:** CPU (collapsible breakdown), memory, Teleport CPU cost, top
    processes
  - **Network:** charts, then uplinks, clients, VPN, interfaces, Wi-Fi,
    radios, nearby networks, events
- Two themes: **Classic** (the default) and **UniFi style**. The choice is
  remembered per browser and applied before first paint.

## Known issues and ideas

- **Future work: downsample older data.** History is kept at full
  resolution for 30 days, and the database grows ~27 MB a day while the
  monitor runs (~800 MB if it ran for all 30). Most of that is the
  per-interface rates in every 2 s sample (~370 bytes) and the
  top-process list in every detail row (~720 bytes). Planned: keep full
  resolution for the last N days, then downsample (for example to 1-minute
  averages) for anything older, with the cut-off configurable. Smaller
  wins: drop hidden interfaces before storing, and store the top-process
  list less often.
- About 17% of CPU at idle can't be attributed to a live process. It's
  consistent with the firmware's daemons constantly starting short-lived
  shell scripts whose time isn't credited to a tracked parent.
- Wired traffic per device would need conntrack byte accounting
  (`nf_conntrack_acct`), which hasn't been checked on this firmware.
- `/api/state` and the dashboard expose MACs and IPs to anyone who can
  reach the port. Keep the default `127.0.0.1` bind unless LAN access is
  needed.
