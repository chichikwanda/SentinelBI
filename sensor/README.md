# SentinelBI sensor

A single Python file (standard library only, Python 3.9 or newer) that turns the packets a machine sees into
flow records and sends them to SentinelBI. It is the "no router setup" way in: enter an IP address when you
register, run one command on that machine, and the platform shows how much data it sent and received, the
hosts and services it talked to, and any alerts.

**Why it has to run somewhere.** A server cannot see the traffic of an arbitrary IP address just because it
is told the address. The packets have to be observed where they pass: on the machine itself, on a gateway, or
on a mirror (SPAN) port. The sensor is the small program that does that and reports back.

## Privacy

Only packet **headers** are used. On Linux just the first 256 bytes of each packet are copied out of the
kernel and the real size comes from the packet's own length; on Windows the whole datagram is received and
everything after the first 256 bytes is discarded at once. Payload bytes are never stored, logged or sent, and
the record format has no field that could carry them (a test feeds a recognisable payload through and checks
it never appears). The sensor does not count its own reports to the server. Run it only on machines and
networks you administer.

## Run it

The setup wizard (Add source, "Quick start") prints these with your API key and address filled in.

```bash
# Linux, as root (or with CAP_NET_RAW and CAP_NET_ADMIN)
curl -fsSO http://YOUR-SERVER:8000/api/v1/sensor/sentinelbi_sensor.py
sudo python3 sentinelbi_sensor.py --self-test
sudo python3 sentinelbi_sensor.py --api-url http://YOUR-SERVER:8000 --api-key sbi_... --ip 192.168.1.20
```

```powershell
# Windows, in an Administrator PowerShell (IPv4 traffic only, see Limits)
Invoke-WebRequest -UseBasicParsing http://YOUR-SERVER:8000/api/v1/sensor/sentinelbi_sensor.py -OutFile sentinelbi_sensor.py
python sentinelbi_sensor.py --self-test
python sentinelbi_sensor.py --api-url http://YOUR-SERVER:8000 --api-key sbi_... --ip 192.168.1.20
```

`--ip` takes an address or network and may be repeated; a packet is kept when either end is inside. Without
`--ip` everything the machine sees is reported. `--self-test` sends one datagram to a documentation address
and checks that the capture sees it leave, so you know capture works before relying on it.

No administrator rights, or just trying it out? Replay the bundled **synthetic** capture (it describes a small
office and contains a 50-port scan; nothing in it was recorded from a real network):

```bash
python sensor/sentinelbi_sensor.py --read-pcap data/samples/sensor_demo.pcap --shift-to-now \
  --map-ip 10.20.0.5=192.168.1.20 --api-url http://127.0.0.1:8000 --api-key sbi_...
```

`--read-pcap` also replays your own classic `.pcap` captures (Ethernet, raw IP or Linux cooked; convert
pcapng first with `editcap -F pcap`). `--dry-run` prints the records as JSON lines instead of sending them.

## Which address to give it

Use the address your traffic really leaves from. A machine often has several: on Windows, `ipconfig` also
lists virtual adapters (vEthernet for WSL and Hyper-V, Docker) that carry almost none of your browsing. Take
the address of the Wi-Fi or Ethernet adapter that has a **Default Gateway**; on Linux, `ip route get 1.1.1.1`
shows it. If you give the sensor a local address that is not the one internet traffic uses, it warns at
start-up and names the address to use, because it would otherwise stay silent: it only reports traffic to or
from the address it was given.

## What a record means

One record per conversation: the client is whoever opened it, `in_bytes` and `in_pkts` count client to server,
`out_bytes` and `out_pkts` count server to client. Bytes are counted at the IP layer, headers included and
Ethernet framing excluded, which is how NetFlow counts them. A connection is reported when it ends or after 15
seconds without packets; a long one is reported every 60 seconds so a large download shows up while it runs.
In the platform, a host's "sent" is what it uploaded and "received" what it downloaded, and sizes use decimal
units (1 kB = 1000 bytes).

## What was tested, and what was not

| | |
|---|---|
| Parsing, flow building, delivery, the command line | 48 automated tests, including one that checks every byte of the demo capture ends up in a flow record |
| Linux live capture | Two containers moving 3.0 MB down and 0.4 MB up: with `NET_ADMIN` the sensor's totals matched the kernel's interface counters to within 0.01% in both directions |
| Linux with `NET_RAW` only | In the same burst the kernel dropped 13 packets from the capture buffer. The sensor reads the kernel's drop counter and prints a warning with the count, so counts are then a lower bound. Run as root or add `--cap-add=NET_ADMIN` |
| Python | Python 3.9.25 and 3.13 produce byte-identical records on the demo capture; CI runs the replay on 3.9 |
| Speed | About 177,000 packets per second per core for parsing, filtering and flow building (offline replay on a laptop; live capture adds a system call per packet) |
| Windows live capture, IPv4 | Tested on the author's laptop from an elevated terminal: the self-test passed, an IPv4-only request showed 9 packets out and 9 in, and a live run reported 141 packets as 14 flows to the real API. ICMP byte counts were exact (4 pings and 4 replies at 60 bytes = 480 B) and the HTTP totals were consistent with the transfer |
| **Windows live capture, IPv6** | **Not captured.** Windows delivers IPv6 raw packets without their IPv6 header (measured: the first bytes are the TCP header), so source and destination addresses cannot be read, and a TCP-specific IPv6 raw socket cannot be opened at all. The sensor prints a note at start-up when the machine has IPv6. See Limits |
| macOS | Not supported for live capture (use `--read-pcap`) |

## Limits

- It reports the packets the operating system hands it. With offloading, "packets" can be larger than the
  wire's MTU; byte totals stay right.
- Capturing on several interfaces of a router counts forwarded traffic once per interface. Pick one with
  `--iface`.
- **Windows capture is IPv4 only, and many machines send most browsing over IPv6** (Windows prefers it
  where a site offers it, and QUIC often uses it). On such a machine the volumes are a lower bound: a plain
  HTTPS request to a dual-stack site produced no IPv4 packets at all in the test above, while an IPv4-only
  request was captured fully. Test with `ping -4 -n 5 1.1.1.1`. Capturing IPv6 on Windows would need a
  capture driver such as Npcap (not implemented); Linux captures both families. Loopback traffic is
  ignored on both systems.
- The API key travels in an HTTP header: use `https://` for anything that crosses an untrusted network.
- Records are posted in batches from a background thread. If the server is unreachable they are kept in memory
  (at most 50,000, oldest dropped first and counted) and sent when it returns.
