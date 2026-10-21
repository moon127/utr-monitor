#!/usr/bin/env python3
"""
utr-probe.py - read-only discovery of what a UniFi Travel Router exposes over SSH.

Runs a fixed list of read-only commands (system info, interfaces, Wi-Fi, VPN,
clients, sensors, config, logs) and writes a text report with secrets redacted.
Nothing on the router is changed.

Usage:
    my-venv/bin/python utr-probe.py 192.168.1.1            # prompts for password
    my-venv/bin/python utr-probe.py 192.168.1.1 -o report.txt

The report still contains MAC addresses, IPs and SSIDs, so don't post it publicly.
"""
import argparse
import importlib.util
import os
import re
import time

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("utr_monitor", os.path.join(HERE, "utr-monitor.py"))
mon = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mon)  # reuse SSHRunner (exec + interactive-shell fallback)

MAX_LINES = 1500
EACH_IF = 'for i in $(ls /sys/class/net); do echo "== $i"; %s; done'

PROBES = [
    ("System", [
        "cat /etc/os-release",
        "cat /etc/version /etc/openwrt_release /etc/board.info 2>&1",
        "uname -a",
        "info",
        "cat /proc/cpuinfo | head -n 25",
        "uptime",
        "df -h",
        "free",
        "ps w 2>/dev/null || ps",
        "ls -1 /bin /sbin /usr/bin /usr/sbin",
    ]),
    ("Interfaces & routing", [
        "ip -br link",
        "ip -br addr",
        "ip -d link",
        "ip route",
        "ip -6 route",
        "ip rule",
        EACH_IF % ('cat /sys/class/net/$i/type /sys/class/net/$i/operstate 2>/dev/null; '
                   'readlink /sys/class/net/$i/device/driver 2>/dev/null; '
                   'ls /sys/class/net/$i/ | grep -E "^(wireless|phy80211|bridge|brport|master)$"; '
                   'readlink /sys/class/net/$i/master 2>/dev/null'),
        "brctl show 2>&1 || bridge link 2>&1",
        "ifconfig -a",
    ]),
    ("Wi-Fi", [
        "iw dev",
        EACH_IF % "iw dev $i info 2>/dev/null; iw dev $i link 2>/dev/null",
        EACH_IF % "iw dev $i station dump 2>/dev/null",
        EACH_IF % 'iw dev $i scan dump 2>/dev/null | grep -E "^BSS|SSID:|signal:|freq:"',
        "iwinfo 2>&1",
        "cat /proc/net/wireless",
        "iw phy 2>&1 | grep -E 'Wiphy|MHz \\[' | head -n 60",
        "cat /etc/config/wireless 2>&1",
    ]),
    ("VPN", [
        "wg show 2>&1",
        "ip -d link show type wireguard 2>&1",
        "ip -d link show type tun 2>&1",
        "ls -la /etc/wireguard /etc/openvpn /etc/teleport 2>&1",
        "ps w | grep -i -E 'wg|wireguard|openvpn|teleport|tailscale|zerotier|ipsec|strongswan' | grep -v grep",
    ]),
    ("Clients, DHCP & DNS", [
        "cat /proc/net/arp",
        "ip neigh",
        "cat /tmp/dhcp.leases /var/lib/misc/dnsmasq.leases /tmp/*.leases 2>&1",
        "cat /etc/resolv.conf /tmp/resolv.conf* 2>&1",
    ]),
    ("Connectivity & capacity", [
        "cat /proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/netfilter/nf_conntrack_max 2>&1",
        "ping -c 3 -W 2 1.1.1.1 2>&1",
        "ping -c 3 -W 2 8.8.8.8 2>&1",
        "netstat -tuln 2>&1 | head -n 40",
    ]),
    ("Hardware sensors", [
        "for z in /sys/class/thermal/thermal_zone*; do echo $z $(cat $z/type) $(cat $z/temp); done 2>&1",
        "cat /sys/class/hwmon/hwmon*/name /sys/class/hwmon/hwmon*/temp*_input 2>&1",
        "ls /sys/class/power_supply 2>&1; cat /sys/class/power_supply/*/uevent 2>&1",
        "ls /sys/class/leds 2>&1",
    ]),
    ("Config", [
        "uci show 2>&1 | head -n 400",
        "cat /etc/config/network 2>&1",
        "ubus list 2>&1 | head -n 80",
        "ls -la /etc /etc/config /etc/persistent 2>&1",
    ]),
    ("Logs", [
        "ls -la /var/log /tmp/log 2>&1",
        "logread 2>&1 | tail -n 200",
        "dmesg 2>&1 | tail -n 120",
        "tail -n 80 /var/log/messages 2>&1",
    ]),
    ("UniFi tooling", [
        "mca-dump 2>&1 | jq . 2>&1",
        "mca-cli-op info 2>&1",
        "head -n 300 /usr/etc/utr_api.sh 2>&1",
        "syswrapper.sh utr-api get-teleport-status 2>&1 | jq . 2>&1",
        "ls -la /tmp/teleport-client.d /etc/persistent/vpn_profiles /etc/persistent/cfg 2>&1",
        "jq . /tmp/teleport-client.d/connection-status.json 2>&1",
        "ls -la /var/run 2>&1 | head -n 150",
        "for f in /var/run/unifi_mwan.status*; do echo \"== $f\"; cat $f; done 2>&1",
        "cat /var/run/uplink_monitor.conf 2>&1",
        "head -n 120 /usr/sbin/utr-runtime-stat-collector 2>&1",
        "tail -n 60 /var/log/utr-runtime-events.log 2>&1",
        "cat /var/log/wpa_hook_log /var/log/ulcmd.log /var/log/fastapply 2>&1",
        "tail -n 60 /var/log/wpas-ath5.log 2>&1",
        "grep -c . /var/log/messages.0; grep -o 'daemon[.a-z]* [a-z_-]*' /var/log/messages.0 | sort | uniq -c | sort -rn | head -n 30",
    ]),
    ("Wi-Fi clients & radios", [
        "for i in ath0 ath1 ath2 ath3; do echo \"== $i\"; hostapd_cli -p /var/run/hostapd -i $i all_sta 2>&1 | head -n 80; done",
        "for i in ath0 ath1 ath2 ath3; do echo \"== $i\"; ubus call hostapd.$i get_clients 2>&1; done",
        "ubus -v list mcagent_stats ui system 2>&1",
        "ubus call system info 2>&1; ubus call system board 2>&1",
        "ethtool eth0 2>&1 | head -n 30; ethtool eth1 2>&1 | grep -E 'Speed|Duplex|Link'",
        "ls /tmp/dnsmasq.conf.d 2>&1; grep -rh -E 'leasefile|dhcp-range|dhcp-host' /tmp/dnsmasq.conf.d /etc/dnsmasq.conf 2>&1 | head -n 20",
        "ls /sys/class 2>&1; cat /etc/config/thermal 2>&1",
    ]),
]

SECRET_RE = re.compile(r"(?i)\b[\w.-]*(?:key|psk|passw\w*|secret|token|private)[\w.-]*\b\s*[:=]?")


def redact(text):
    out = []
    for ln in text.splitlines():
        m = SECRET_RE.search(ln)
        if m and not ln.lstrip().startswith(("$", "==")):
            ln = ln[:m.end()] + " <redacted>"
        out.append(ln)
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="Read-only discovery of a UTR's SSH environment.")
    ap.add_argument("host")
    ap.add_argument("-u", "--user", default="ui")
    ap.add_argument("-p", "--password", help="else $UTR_PASSWORD, else the monitor's saved password, else prompt")
    ap.add_argument("--ssh-port", type=int, default=22)
    ap.add_argument("-s", "--section", help="comma-separated: only run sections whose name contains one of these")
    ap.add_argument("-o", "--output", default=os.path.join(HERE, "utr-probe-report.txt"))
    a = ap.parse_args()
    pw, _ = mon.resolve_password(a.user, a.host, a.password)

    runner = mon.SSHRunner(a.host, a.user, pw, port=a.ssh_port, timeout=15)
    lines = [f"# UTR probe report - {a.host} - {time.strftime('%Y-%m-%d %H:%M:%S %Z')}"]
    ok = failed = 0
    for section, cmds in PROBES:
        if a.section and not any(w.strip().lower() in section.lower() for w in a.section.split(",")):
            continue
        lines.append(f"\n\n########## {section} ##########")
        print(f"[{section}]")
        for cmd in cmds:
            try:
                out = runner.run(cmd).strip("\n")
                ok += 1
            except Exception as e:
                out = f"!! failed: {e}"
                failed += 1
                runner.close()  # reconnect cleanly for the next command
            body = out.splitlines()
            if len(body) > MAX_LINES:
                body = body[:MAX_LINES] + [f"... ({len(body) - MAX_LINES} more lines truncated)"]
            lines += [f"\n$ {cmd}", redact("\n".join(body)) or "(no output)"]
            print(f"  {'ok ' if not out.startswith('!!') else 'ERR'} {cmd[:90]}")
    lines.insert(1, f"# ssh mode: {runner.mode}; commands ok: {ok}, failed: {failed}")
    runner.close()
    with open(a.output, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"\nReport written to {a.output}")


if __name__ == "__main__":
    main()
