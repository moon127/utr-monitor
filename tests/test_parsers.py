"""Fast-poll parsers and small helpers."""
import helpers


def test_parse_proc_stat(mon):
    assert mon.parse_proc_stat("intr 1\ncpu  100 0 50 800 10 0 20 0\n") == (980, 810)
    assert mon.parse_proc_stat("cpu  1 2 3 4\n") == (10, 4)   # short line padded with zeros
    assert mon.parse_proc_stat("nothing here") is None


def test_parse_meminfo(mon):
    assert mon.parse_meminfo(helpers.MEMINFO) == (250000, 100000)
    # Older kernels without MemAvailable: free + buffers + cache are treated as available
    old = "MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 50 kB\nCached: 250 kB\n"
    assert mon.parse_meminfo(old) == (1000, 600)
    assert mon.parse_meminfo("garbage") is None


def test_parse_net_proc_format(mon):
    assert mon.parse_net(helpers.NET_DEV) == {"lo": (10, 10), "eth0": (1000, 2000), "wg0": (500, 600)}
    assert mon.parse_net("Inter-|\n  eth9: 1 2 3\n") == {}   # too few fields


def test_parse_net_ifconfig_formats(mon):
    text = ("eth0      Link encap:Ethernet  HWaddr AA\n"
            "          RX bytes:123 (120 B)  TX bytes:456 (456 B)\n\n"
            "wlan0: flags=4163<UP>  mtu 1500\n"
            "        RX packets 50  bytes 1000 (1.0 KB)\n"
            "        TX packets 60  bytes 2000 (2.0 KB)\n\n"
            "half0: flags=1\n        RX packets 1  bytes 5\n")
    assert mon.parse_net(text) == {"eth0": (123, 456), "wlan0": (1000, 2000)}
    assert mon.parse_net("          RX bytes:1 TX bytes:2\n") == {}   # counters before any interface name


def test_parse_top(mon):
    top = ("Mem: 180000K used, 332000K free, 0K shrd, 8000K buff, 60000K cached\n"
           "CPU:   3% usr   2% sys   0% nic  94% idle   0% io   0% irq   0% sirq\n"
           "Load average: 0.12 0.20 0.18 1/90 2345")
    assert mon.parse_top(top) == {"mem": (512000, 112000), "cpu": 6.0, "load1": 0.12}
    assert mon.parse_top("Mem: 10K used, 10K free") == {"mem": (20, 10)}
    assert mon.parse_top("") == {}


def test_small_helpers(mon):
    assert mon._num("1.5") == 1.5 and mon._num(None) is None and mon._num("x") is None
    assert mon._sat(-1) is None and mon._sat("90") == 90.0 and mon._sat(None) is None
    assert mon._json('{"a": 1}') == {"a": 1}
    assert mon._json("", default=[]) == [] and mon._json("{bad", default=0) == 0


def test_parse_procs_and_labels(mon):
    stat = "\n".join([
        helpers.stat_line(1, "procd", 0, 5, 7, 1),
        helpers.stat_line(40, "kworker/u8:1", 2, 3, 0, 2),
        helpers.stat_line(50, "my (odd) name", 1, 1, 0, 3),   # parentheses inside comm
        helpers.stat_line(60, "sh", 1, 1, 0, 3),
        helpers.stat_line(61, "sh", 1, 1, 0, 3),
        "garbage", "70 (short) S",
    ])
    ps = "  PID USER VSZ STAT COMMAND\n60 ui 1 S sh -c syswrapper.sh utr-api get-teleport-status\nx\n"
    procs = mon.parse_procs(stat, ps)
    assert set(procs) == {1, 40, 50, 60, 61}
    assert procs[1] == {"pid": 1, "comm": "procd", "ppid": 0, "own": 5, "child": 7, "start": 1, "cmd": ""}
    assert procs[50]["comm"] == "my (odd) name"
    assert mon._proc_label(procs[40]) == "[kworker/u8:1]"
    assert mon._proc_label(procs[60]).startswith("sh -c syswrapper.sh")
    assert mon._proc_label(procs[61]) == "sh"           # shell without a known command line
    assert mon._proc_label({"pid": 2, "ppid": 0, "comm": "kthreadd", "cmd": ""}) == "[kthreadd]"
