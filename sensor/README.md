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
# Windows, in an Administrator PowerShell. Install Npcap first (below) to capture IPv6 as well
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

## Capture backends, and why Windows wants Npcap

The sensor captures one of two ways, and says which at start-up.

- **libpcap / Npcap** (default on Windows and macOS when installed, `--backend pcap` anywhere): sees IPv4 **and
  IPv6** with full headers. On Windows it needs [Npcap](https://npcap.com) (the capture driver Wireshark and
  Nmap use). Npcap's free licence allows installs on up to 5 systems and forbids redistribution, and a silent
  installer is a paid-edition feature, so SentinelBI does not bundle it: you download and install it yourself
  (accept the defaults) and the sensor finds it. For use beyond that licence, capture on Linux instead.
- **Native** (Linux packet socket; the Windows raw socket as the fallback when Npcap is missing): the Linux
  socket sees both families; the Windows raw socket is **IPv4 only**, because Windows hands IPv6 raw packets to
  programs without their IPv6 header.

`--list-devices` shows what libpcap can capture on, and `--iface` takes a device name or part of its
description (Windows device names are long GUIDs, the description is easier). `--promiscuous` also sees
packets not addressed to this machine, for a gateway or mirror port.

**`--check`** is the one command to run after installing Npcap, or whenever volumes look too low. It runs the
self-test, then makes one short web request over IPv4 and one over IPv6 from this machine and counts how many
of those packets the capture saw in each direction. It prints one verdict per family (`OK`, `NOT SEEN` with the
likely cause, or `not testable here` when the machine has no route for that family, which is not a capture
fault) and exits 0 only when every family it could test was seen. It needs the same rights as live capture
(an Administrator PowerShell on Windows, `sudo` on Linux) and about 15 seconds. The requests go to
`example.com` on port 80 and nothing is sent to SentinelBI.

**One address is enough for the whole machine.** A dual-stack machine is several addresses: the IPv4 address you
type, plus IPv6 addresses on the same adapter, several of them temporary ones that change daily. When you give a
single address and the capture is libpcap/Npcap, the sensor looks up the other addresses of that adapter
(loopback, link-local and multicast ones are skipped), watches them too, checks again every minute, and tells the
server through `PUT /api/v1/sensor/addresses` (authenticated with the same API key) so the Traffic page counts
them as the same monitored machine. Each shows as its own row there. The server keeps the newest 64 per source.
On the laptop this was built on, nearly all traffic was IPv6: the IPv4 address alone showed about 4 kB where the
machine had moved 27 MB. With a capture that cannot list addresses (the Linux packet socket, the Windows raw
socket) the sensor says so and you give the IPv6 address or prefix yourself, for example
`--ip 192.168.1.20 --ip 2001:db8:1::/64`, or use `--backend pcap`. A range (`--ip 10.0.0.0/24`) is never
extended, and `--dry-run` shows what would be watched without telling the server. An older server answers 404
to the announcement: the sensor says so and still captures, but only registered addresses count as monitored.

Npcap's default install lets any user capture, and the sensor worked without Administrator rights on the
laptop it was tested on. If you ticked "Restrict Npcap driver's access to Administrators only" while installing,
use an Administrator terminal.

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
| libpcap backend, Linux | The ctypes wrapper against real libpcap, capturing IPv4 and IPv6 transfers: byte-identical flows to the native backend, and within 0.021% (transmit) and 0.006% (receive) of the kernel's interface counters |
| Windows live capture through Npcap 1.90, IPv4 and IPv6 | Tested on the author's laptop (Wi-Fi, dual-stack, Python 3.13) against the real stack, **without Administrator rights** (Npcap's default install). The device list found the adapter with its IPv4 and three IPv6 addresses; the self-test passed; `--check` passed three runs in a row for both families. A 75-second live run reported 27 MB: 5 pings over IPv4 to 1.1.1.1 came out as exactly 600 bytes and 5 over IPv6 as exactly 800, and the total plus 14 bytes of Ethernet header per packet was within 0.11% of Windows' own adapter counters (`Get-NetAdapterStatistics`; the difference includes local-network chatter the sensor correctly ignores). 99.99% of that traffic was IPv6. Windows 11 only; Windows 10 and other adapters are untested |
| Windows IPv6 through the raw-socket fallback | **Not captured** (measured: Windows delivers the TCP header first, with no IPv6 header, and a TCP-specific IPv6 raw socket cannot be opened). The sensor prints a note at start-up when the machine has IPv6 |
| `--check` | Linux with both backends on a dual-stack network (IPv4 OK, IPv6 OK, exit 0); Windows without Npcap (reports a clear refusal or IPv4 only); Windows with Npcap (passes). It first reported IPv6 as NOT SEEN on Windows because Npcap hands packets over in batches up to half a second late and the check stopped listening a second after the request began; it now listens 2 seconds after the request ends, and a test reproduces the late delivery |
| One address covering the whole machine | Unit tests (address discovery, the matcher's cache, the announcement and its retries, a full run with a fake adapter), 9 backend tests (authorisation, limits, isolation between organisations, the Traffic page counting an announced address byte for byte), and the live Windows run above, where the server listed the adapter's three IPv6 addresses and the Traffic page showed the IPv6 host |
| macOS | libpcap is built in and the backend is selected, but it is untested |

## Limits

- It reports the packets the operating system hands it. With offloading, "packets" can be larger than the
  wire's MTU; byte totals stay right.
- Capturing on several interfaces of a router counts forwarded traffic once per interface. Pick one with
  `--iface`.
- **Without Npcap, Windows capture is IPv4 only, and many machines send most browsing over IPv6** (Windows
  prefers it where a site offers it, and QUIC often uses it). On such a machine the volumes are a lower bound:
  a plain HTTPS request to a dual-stack site produced no IPv4 packets at all in the test above, while an
  IPv4-only request was captured fully. Test with `ping -4 -n 5 1.1.1.1`, and install Npcap for IPv6.
  Loopback traffic is ignored on both systems.
- A batch is sent with an `Idempotency-Key` (a hash of its records), so if a reply is lost and the batch is
  resent, the server counts it once. The server remembers keys for an hour; replaying the same capture file
  unshifted within that hour is therefore recognised as repeated data and ignored (the sensor reports how
  many batches that applied to). `--shift-to-now` gives each replay new timestamps and so new data.
- The API key travels in an HTTP header: use `https://` for anything that crosses an untrusted network.
- Records are posted in batches from a background thread. If the server is unreachable they are kept in memory
  (at most 50,000, oldest dropped first and counted) and sent when it returns.
