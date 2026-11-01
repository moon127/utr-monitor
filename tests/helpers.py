"""Fictional router output in the shapes the UTR (firmware 6.6.x) produces.

Nothing here comes from a real device: names, MACs and addresses are made up.
"""
import json

SEP = "@@UTR_SECTION@@"
PROC_SEP = "@@UTR_PROCS@@"

PHONE = "aa:00:00:00:00:01"
LAPTOP = "aa:00:00:00:00:02"
TABLET = "aa:00:00:00:00:03"
WIRED = "aa:00:00:00:00:09"
LEFT = "aa:00:00:00:00:0a"      # Wi-Fi client that has left: ARP entry lingers on br-lan
UPLINK_BSSID = "02:00:00:00:00:01"

PROC_STAT = "cpu  100 0 50 800 10 0 20 0 0 0\n"
MEMINFO = "MemTotal: 250000 kB\nMemFree: 100000 kB\nMemAvailable: 150000 kB\n"
NET_DEV = ("Inter-|   Receive |  Transmit\n face |bytes packets|bytes\n"
           "    lo: 10 0 0 0 0 0 0 0 10 0 0 0 0 0 0 0\n"
           "  eth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0\n"
           "  wg0: 500 0 0 0 0 0 0 0 600 0 0 0 0 0 0 0\n")


def proc_output(stat=PROC_STAT, mem=MEMINFO, net=NET_DEV, load="0.50 0.40 0.30 1/80 999",
                uptime=" 10:00:00 up 1 day,  load average: 0.50, 0.40, 0.30"):
    return f"{stat}{SEP}\n{mem}{SEP}\n{net}{SEP}\n{load}\n{SEP}\n{uptime}"


def mca(now, **over):
    sta = [
        {"mac": PHONE, "hostname": "Phone", "ip": "192.168.29.21", "signal": -45, "rx_rate": 866000,
         "tx_rate": 780000, "tx_mcs": 9, "uptime": 600, "idletime": 1, "rx_bytes": 1000,
         "tx_bytes": 5000, "satisfaction": 98, "is_11ac": True, "is_11n": True},
        {"mac": LAPTOP, "ip": "", "signal": -62, "rx_rate": 400000, "tx_rate": 360000,
         "tx_mcs": 7, "uptime": 300, "idletime": 0, "rx_bytes": 200, "tx_bytes": 900,
         "satisfaction": 80, "is_11ax": True},
        {"mac": TABLET, "hostname": "Tablet", "ip": "192.168.29.23", "signal": -75,
         "satisfaction": -1, "is_11n": True},
        {"mac": "aa:00:00:00:00:04", "hostname": "Old", "ip": "192.168.29.24", "signal": -80},
    ]
    data = {
        "hostname": "Test-UTR", "model_display": "UniFi Travel Router", "version": "6.6.122",
        "uptime": 1000, "time": int(now), "internet": True, "uplink": "eth0", "satisfaction": 95,
        "lan_ip": "192.168.29.1", "gateway_ip": "192.168.1.1",
        "system-stats": {"cpu": "30.5", "mem": "52.0"},
        "portal_detect": [{"wan_if": "eth0", "state": "open", "default_route": True},
                          {"wan_if": "ath4", "state": "unknown"},
                          {"wan_if": "ath5", "state": "open"},
                          {"wan_if": "usb0", "state": "unknown"},
                          {"wan_if": "ppp0", "state": "unknown"},
                          {"state": "no interface"}],
        "lldp_table": [{"local_port_name": "eth0", "chassis_descr": "Test Switch", "port_descr": "Port 3"},
                       {"local_port_name": "ath5", "chassis_id": "02:00:00:00:00:fe", "port_id": UPLINK_BSSID}],
        "lan_table": [{"interface": "eth1", "speed": 1000}, {"interface": "ath1"}, {"interface": "eth2"}, {}],
        "vap_table": [
            {"name": "ath1", "essid": "TravelNet", "radio": "na", "channel": 36, "bw": 80, "num_sta": 4,
             "tx_power": 11, "satisfaction": 94, "usage": "user", "up": True, "sta_table": sta},
            {"name": "ath0", "essid": "TravelNet", "radio": "ng", "channel": 6, "bw": 20,
             "satisfaction": -1, "usage": "user", "up": True},
            {"name": "ath5", "essid": "Hotel", "radio": "na", "channel": 36, "bw": 80,
             "usage": "wireless-bridge", "up": True, "bssid": UPLINK_BSSID.upper()},
            {"name": "ath4", "essid": "", "radio": "ng", "channel": 6, "bw": 20, "usage": "wireless-bridge"},
        ],
        "radio_table": [
            {"name": "wifi0", "radio": "ng", "max_txpower": 13, "nss": 2,
             "athstats": {"cu_total": 12, "cu_self_tx": 2, "cu_self_rx": 1, "noise_floor": -95, "satisfaction": -1},
             "scan_table": [{"essid": "Cafe", "bssid": "02:00:00:00:01:01", "band": "ng", "channel": 1,
                             "signal": -71, "security": "WPA2-Personal", "is_unifi": False}]},
            {"name": "wifi1", "radio": "na", "athstats": {"cu_total": 8, "noise_floor": -96, "satisfaction": 90},
             "scan_table": [{"essid": "Hotel", "bssid": UPLINK_BSSID, "band": "na", "channel": 36, "bw": 80,
                             "signal": -58, "security": "Open", "is_unifi": True, "model_display": "U6-LR"},
                            {"bssid": "02:00:00:00:01:02", "band": "na", "channel": 44, "signal": None}]},
            {"name": "wifi2", "radio": "6e"},
        ],
    }
    data.update(over)
    return data


def events_log():
    lines = [
        {"ts": 39, "monotonic": 40, "category": "collector", "event": "started", "details": {"interval": "10"}},
        {"ts": 1700000000, "monotonic": 56, "category": "internet", "event": "internet_on",
         "details": {"iface": "eth0", "portal_state": "open"}},
        {"ts": 1700000100, "category": "vpn", "event": "vpn_on",
         "details": {"new": "openvpn=missing;teleport=CONNECTED;wireguard=missing"}},
        {"monotonic": 80, "category": "bt", "event": "bt_connected", "details": "not-a-dict"},
        {"category": "nowhen", "event": "skipped"},
    ]
    return "\n".join([json.dumps(x) for x in lines] + ["not json", "{broken", "[1, 2]"])


def detail_output(now, mca_data=None, teleport=True, wireless=None, fdb=True, extra_proc=""):
    m = mca(now) if mca_data is None else mca_data
    tele = {"state": "CONNECTED", "detailed_status": "CONNECTED", "site_name": "Home", "uptime_seconds": 120,
            "client_ip": "192.168.2.25", "endpoint": "203.0.113.1:51820", "rx_bytes": 10, "tx_bytes": 20,
            "killswitch_enabled": False, "internet_state": "open", "profile_id": "1"}
    ping = {"latency": [{"target": "1.1.1.1", "latency_ms": 4}, {"target": "8.8.8.8", "latency_ms": 6},
                        {"target": "x", "latency_ms": None}, "junk"]}
    sections = [
        json.dumps(m) if m != "" else "",
        json.dumps(tele) if teleport is True else (teleport or ""),
        f"wg0\tPEER=\t{int(now) - 30}\nwg0\tPEER2=\t0\nwg1\tbad\tnotnum",
        "wg0\tPEER=\t100\t200\nwg0\tPEER2=\t1\t2\nwg2\tP\tx\ty",
        f"eth0 {json.dumps(ping)}\nath5 {json.dumps({'latency': []})}\nusb0 not-json\nath4 [1]",
        f"0 {LAPTOP.upper()} 192.168.29.22 Laptop *\n0 {WIRED} 192.168.29.50 Desktop *\n0 bb:00:00:00:00:01 1.2.3.4 * *\nshort",
        ("IP address HW type Flags HW address Mask Device\n"
         f"192.168.29.50 0x1 0x2 {WIRED} * br-lan\n"
         f"192.168.29.60 0x1 0x2 {LEFT} * br-lan\n"
         "192.168.29.61 0x1 0x2 aa:00:00:00:00:0b * br-lan2\n"
         "192.168.1.1 0x1 0x2 02:00:00:00:00:fe * eth0\n"
         "192.168.29.70 0x1 0x0 00:00:00:00:00:00 * br-lan"),
        events_log(),
        "default via 192.168.1.1 dev eth0 metric 100\ndefault via 192.168.1.1 dev ath5 metric 200\ndefault via 10.0.0.1",
        ("2: eth0    inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0\n"
         "9: ath5    inet 192.168.1.51/24 scope global ath5\n"
         "12: ath4    inet 169.254.1.20/16 scope link ath4\n"
         "10: br-lan    inet 192.168.29.1/24 scope global br-lan\n"
         "2: eth0    inet 192.168.1.99/24 secondary"),
        wireless if wireless is not None else ("Inter-| sta-|\n face | tus |\n"
                                               "  ath5: 0005   44.  -55.  -96.   0 0 0 0 0 0\n"
                                               "  ath4: 0000   0.  -96.  -101.  0 0 0 0 0 0\n"
                                               "  junk line"),
        "1000.00 4000.00\nboot-1234\n6.6.122",
        ("port no\tmac addr\t\tis local?\tageing timer\n"
         f"  1\t{WIRED}\tno\t\t   0.10\n"
         f"  2\t{LEFT}\tno\t\t   0.50\n"
         "  1\t8c:00:00:00:00:01\tyes\t\t   0.00\n"
         "  x\tbad\tno\t0") if fdb else "",
        "eth1 0x1\nath1 0x2\nbad notanumber\nlonely" if fdb else "",
    ]
    out = f"\n{SEP}\n".join(sections)
    return out + (f"\n{PROC_SEP}\n{extra_proc}" if extra_proc else "")


# ---- per-process CPU accounting snapshots -----------------------------------
def stat_line(pid, comm, ppid, own, child, start):
    return f"{pid} ({comm}) S {ppid} 0 0 0 0 0 0 0 0 0 {own} 0 {child} 0 20 0 1 0 {start} 0 0"


def proc_snapshot(shell_pid, uptime, cpu, procs, cmds=None, net=None, ncpu=4):
    """cpu: 8 cumulative tick counters; procs: list of (pid, comm, ppid, own, child, start)."""
    cpu_lines = "cpu  " + " ".join(map(str, cpu)) + "\n" + "".join(f"cpu{i} 0 0 0 0 0 0 0 0\n" for i in range(ncpu))
    stats = "\n".join(stat_line(*p) for p in procs) + "\n9999 (broken\n12 (x) S notanumber"
    ps = "  PID USER       VSZ STAT COMMAND\n" + "".join(
        f"{pid} ui 1000 S {cmd}\n" for pid, cmd in (cmds or {}).items()) + "junk\n"
    nd = net if net is not None else NET_DEV
    return f"{shell_pid}\n{uptime} 1000.0\n{cpu_lines}{SEP}\n{nd}{SEP}\n{stats}\n{SEP}\n{ps}"
