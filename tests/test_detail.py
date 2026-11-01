"""parse_detail: the UniFi tooling poll (mca-dump, Teleport, multi-WAN, leases, events...)."""
import helpers

NOW = 1_800_000_000.0


def parse(mon, **kw):
    return mon.parse_detail(helpers.detail_output(NOW, **kw), NOW)


def test_system_and_ifaces(mon):
    state, series, _ = parse(mon)
    sysinfo = state["system"]
    assert sysinfo["hostname"] == "Test-UTR" and sysinfo["firmware"] == "6.6.122"
    assert sysinfo["active_wan"] == "eth0" and sysinfo["cpu"] == 30.5 and sysinfo["mca"] is True
    assert sysinfo["uptime"] == 1000.0
    labels = {k: v["label"] for k, v in state["ifaces"].items()}
    assert labels["eth0"] == "WAN · Ethernet (active)"
    assert labels["ath5"] == "WAN · Wi-Fi Hotel 5 GHz"
    assert labels["ath4"] == "WAN · Wi-Fi uplink 2.4 GHz"      # bridge with no network name
    assert labels["usb0"] == "WAN · USB tether"
    assert labels["ppp0"] == "WAN · ppp0"
    assert labels["wg0"] == "VPN · Teleport"
    assert labels["ath1"] == "Wi-Fi · TravelNet 5 GHz" and labels["ath0"] == "Wi-Fi · TravelNet 2.4 GHz"
    assert labels["eth1"] == "LAN port" and labels["eth2"] == "LAN port" and labels["br-lan"] == "LAN · all clients"
    assert series["vpn"] == 1 and series["ncl"] == 4


def test_wans(mon):
    state, series, _ = parse(mon)
    wans = {w["iface"]: w for w in state["wans"]}
    assert [w["iface"] for w in state["wans"]][0] == "eth0"            # active first
    assert wans["eth0"]["latency"] == 5.0 and wans["eth0"]["neighbour"] == "Test Switch · Port 3"
    assert wans["eth0"]["targets"]["1.1.1.1"] == 4.0
    # Link-local address means no real lease: not connected, no signal
    assert wans["ath4"]["connected"] is False and wans["ath4"]["signal"] is None
    # Associated Wi-Fi uplink takes its live signal from /proc/net/wireless
    assert wans["ath5"]["connected"] is True and wans["ath5"]["signal"] == -55.0
    assert wans["ath5"]["latency"] is None                              # empty ping result
    assert wans["ath5"]["neighbour"] == f"02:00:00:00:00:fe · {helpers.UPLINK_BSSID}"
    assert series["lat"] == {"eth0": 5.0, "ath5": None} and series["usig"] == -55.0


def test_uplink_signal_falls_back_to_scan_table(mon):
    state, _, _ = parse(mon, wireless="  ath5: 0000   0.  -96.  -101.   0 0 0 0 0 0")
    assert {w["iface"]: w for w in state["wans"]}["ath5"]["signal"] == -58   # from the radio scan


def test_wans_without_portal_detect(mon):
    m = helpers.mca(NOW, portal_detect=[], uplink=None)
    state, _, _ = parse(mon, mca_data=m)
    # Falls back to default routes plus Wi-Fi bridges, and the lowest-metric route is active
    assert {w["iface"] for w in state["wans"]} == {"eth0", "ath5", "ath4"}
    assert state["system"]["active_wan"] == "eth0"


def test_vpn(mon):
    state, _, _ = parse(mon)
    assert state["vpn"]["teleport"]["site_name"] == "Home"
    assert state["vpn"]["wg"]["wg0"] == {"handshake_age": 30, "rx_bytes": 101, "tx_bytes": 202}
    assert "wg1" not in state["vpn"]["wg"] and "wg2" not in state["vpn"]["wg"]


def test_vpn_wireguard_only_and_stale(mon):
    state, series, _ = parse(mon, teleport="")
    assert state["vpn"]["teleport"] is None
    assert state["ifaces"]["wg0"]["label"] == "VPN · WireGuard"
    assert series["vpn"] == 1                         # recent handshake
    state, _, _ = parse(mon, teleport="[1, 2]")       # not a dict
    assert state["vpn"]["teleport"] is None


def test_clients(mon):
    state, _, _ = parse(mon)
    c = {x["mac"]: x for x in state["clients"]}
    assert set(c) == {helpers.PHONE, helpers.LAPTOP, helpers.TABLET, "aa:00:00:00:00:04", helpers.WIRED}
    assert c[helpers.PHONE]["std"] == "Wi-Fi 5" and c[helpers.PHONE]["conn"] == "TravelNet · 5 GHz"
    # Name and IP come from the DHCP lease when mca-dump doesn't have them
    assert c[helpers.LAPTOP]["name"] == "Laptop" and c[helpers.LAPTOP]["ip"] == "192.168.29.22"
    assert c[helpers.LAPTOP]["std"] == "Wi-Fi 6" and c[helpers.TABLET]["std"] == "Wi-Fi 4"
    assert c["aa:00:00:00:00:04"]["std"] == "legacy" and c[helpers.TABLET]["satisfaction"] is None
    wired = c[helpers.WIRED]
    assert wired["wired"] and wired["iface"] == "eth1" and wired["conn"] == "Wired · LAN port"
    assert wired["name"] == "Desktop" and wired["tx_rate"] == 1_000_000
    # LEFT is on a Wi-Fi bridge port in the FDB, so it isn't mistaken for a wired client
    assert helpers.LEFT not in c


def test_wired_clients_without_fdb(mon):
    state, _, _ = parse(mon, fdb=False)
    wired = [x for x in state["clients"] if x["wired"]]
    # Without brctl the ARP table is all there is, so lingering entries count (documented limitation)
    assert {x["mac"] for x in wired} == {helpers.WIRED, helpers.LEFT, "aa:00:00:00:00:0b"}
    assert {x["conn"] for x in wired} == {"Wired · LAN port"}


def test_wired_client_on_unexpected_port(mon):
    m = helpers.mca(NOW, lan_table=[])
    out = helpers.detail_output(NOW, mca_data=m).replace("eth1 0x1", "lan9 0x1")
    state, _, _ = mon.parse_detail(out, NOW)
    wired = [x for x in state["clients"] if x["wired"]]
    assert wired[0]["conn"] == "Wired · lan9" and wired[0]["tx_rate"] is None


def test_radios_vaps_neighbours(mon):
    state, series, _ = parse(mon)
    r = {x["name"]: x for x in state["radios"]}
    assert r["wifi0"]["channel"] == 6 and r["wifi0"]["cu_total"] == 12 and r["wifi0"]["satisfaction"] is None
    assert r["wifi1"]["satisfaction"] == 90.0 and r["wifi2"]["band"] == "6 GHz" and r["wifi2"]["channel"] is None
    assert series["cu"] == {"2.4 GHz": 12, "5 GHz": 8}
    assert all("_sta" not in v for v in state["vaps"])
    assert state["neighbours"][0]["essid"] == "Hotel" and state["neighbours"][0]["model"] == "U6-LR"
    assert state["neighbours"][-1]["signal"] is None


def test_events(mon):
    _, _, events = parse(mon)
    boot = NOW - 1000.0
    by_event = {e["event"]: e for e in events}
    assert set(by_event) == {"started", "internet_on", "vpn_on", "bt_connected"}
    # Times come from boot time + monotonic counter, not the (possibly pre-NTP) wall clock
    assert by_event["started"]["t"] == boot + 40 and by_event["internet_on"]["t"] == boot + 56
    assert by_event["vpn_on"]["t"] == 1700000100     # no monotonic: falls back to ts
    assert by_event["bt_connected"]["details"] == {}
    # IDs are stable across polls
    _, _, again = parse(mon)
    assert [e["id"] for e in events] == [e["id"] for e in again]


def test_degrades_without_mca(mon):
    out = helpers.detail_output(NOW, mca_data="")
    state, series, events = mon.parse_detail(out, NOW)
    assert state["system"]["mca"] is False and state["vaps"] == [] and state["clients"][0]["wired"]
    assert state["system"]["active_wan"] == "eth0"       # from the routing table
    assert events                                         # event log still parsed
    state, _, _ = mon.parse_detail("[1, 2]", NOW)          # mca-dump returned a non-object
    assert state["system"]["mca"] is False and state["wans"] == []


def test_uptime_from_mca_when_proc_uptime_missing(mon):
    out = helpers.detail_output(NOW).replace("1000.00 4000.00\nboot-1234\n6.6.122", "")
    state, _, events = mon.parse_detail(out, NOW)
    assert state["system"]["uptime"] == 1000.0 and state["system"]["firmware"] == "6.6.122"
    assert events
