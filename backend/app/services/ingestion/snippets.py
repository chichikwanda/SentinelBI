"""Setup instructions shown by the onboarding wizard.

An IP address alone gives the platform no visibility (plan section 1), so registering a source
must tell the user how traffic will actually reach us: collector address, API key, and
copy-paste router configuration.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from app.core.config import Settings
from app.core.enums import SourceMethod
from app.schemas.common import host_form
from app.services.ingestion.sensor_script import load_sensor_script


@dataclass(frozen=True)
class Snippet:
    id: str
    title: str
    language: str
    content: str


@dataclass(frozen=True)
class SetupInfo:
    collector_host: str
    collector_port: int
    api_url: str
    snippets: list[Snippet]


def build_setup_info(
    method: SourceMethod, api_key: str, settings: Settings, cidr: str | None = None
) -> SetupInfo:
    host, port, api = (
        settings.collector_public_host,
        settings.collector_public_port,
        settings.api_public_url.rstrip("/"),
    )
    snippets: list[Snippet] = []

    if method is SourceMethod.NETFLOW:
        snippets += [
            Snippet(
                "mikrotik",
                "MikroTik RouterOS",
                "shell",
                f"/ip traffic-flow set enabled=yes interfaces=all\n"
                f"/ip traffic-flow target add dst-address={host} port={port} version=9",
            ),
            Snippet(
                "pfsense",
                "pfSense",
                "text",
                f"Install the softflowd package (System > Package Manager), then set\n"
                f"  Host: {host}   Port: {port}   NetFlow version: 9\n"
                f"and select the interfaces to export.",
            ),
            Snippet(
                "cisco",
                "Cisco IOS",
                "shell",
                f"ip flow-export destination {host} {port}\n"
                f"ip flow-export version 9\n"
                f"interface <wan-or-lan-interface>\n"
                f" ip flow ingress",
            ),
        ]
    if method is SourceMethod.HTTP:
        snippets.append(
            Snippet(
                "curl",
                "HTTP batch API (curl)",
                "shell",
                f"curl -X POST {api}/api/v1/ingest/flows \\\n"
                f'  -H "X-API-Key: {api_key}" -H "Content-Type: application/json" \\\n'
                f'  -d \'{{"flows":[{{"src_ip":"10.0.0.5","dst_ip":"198.51.100.7",'
                f'"src_port":51514,"dst_port":443,"protocol":6,"tcp_flags":27,'
                f'"in_bytes":1200,"out_bytes":5400,"in_pkts":10,"out_pkts":12,'
                f'"duration_ms":850}}]}}\'',
            )
        )
        snippets.append(
            Snippet(
                "replay",
                "Replay the synthetic demo CSV",
                "shell",
                f"docker compose run --rm migrate python -m app.services.ingestion.csv_replay \\\n"
                f"  --file /repo/data/samples/synthetic_flows.csv --api-url http://api:8000 \\\n"
                f"  --api-key {api_key}",
            )
        )
    if method is SourceMethod.SENSOR:
        snippets += _sensor_snippets(api, api_key, host_form(cidr or ""), settings)
    return SetupInfo(host, port, api, snippets)


def _demo_host(cidr: str) -> str:
    """An address inside the watched range to map the demo capture onto."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return "10.20.0.5"
    return str(net.network_address if net.num_addresses == 1 else net.network_address + 1)


def _sensor_snippets(api: str, key: str, cidr: str, settings: Settings) -> list[Snippet]:
    """Commands that run the sensor on the machine (or gateway) that sees the traffic."""
    script = load_sensor_script(settings.sensor_script_path)
    url = f"{api}/api/v1/sensor/sentinelbi_sensor.py"
    run = f"--api-url {api} --api-key {key} --ip {cidr}"
    check = (
        f"expected SHA-256: {script.sha256}"
        if script
        else "(this server could not read the script)"
    )
    snippets = [
        Snippet(
            "sensor-windows",
            "Windows",
            "shell",
            "# Run in an ADMINISTRATOR PowerShell on the machine you want to watch (needs Python 3.9+).\n"
            "# Optional, recommended: install Npcap first (https://npcap.com, free for personal use) so IPv6\n"
            "# traffic is counted too; without it only IPv4 is captured on Windows.\n"
            f"Invoke-WebRequest -UseBasicParsing {url} -OutFile sentinelbi_sensor.py\n"
            f"Get-FileHash sentinelbi_sensor.py -Algorithm SHA256   # {check}\n"
            "python sentinelbi_sensor.py --self-test\n"
            f"python sentinelbi_sensor.py {run}",
        ),
        Snippet(
            "sensor-service",
            "Run in the background (Windows)",
            "shell",
            "# Run ONCE in an ADMINISTRATOR PowerShell. The sensor then starts with Windows and restarts\n"
            "# itself: no terminal to keep open. Needs Python 3.9+ installed for ALL users.\n"
            f"Invoke-WebRequest -UseBasicParsing {url} -OutFile sentinelbi_sensor.py\n"
            f"Invoke-WebRequest -UseBasicParsing {api}/api/v1/sensor/install-service.ps1 "
            "-OutFile install-service.ps1\n"
            "powershell -ExecutionPolicy Bypass -File .\\install-service.ps1 "
            f"-ApiUrl {api} -ApiKey {key} -Ip {cidr}",
        ),
        Snippet(
            "sensor-linux",
            "Linux",
            "shell",
            "# Run on the machine (or gateway) that sees the traffic. Needs Python 3.9+ and root.\n"
            f"curl -fsSO {url}\n"
            f"sha256sum sentinelbi_sensor.py   # {check}\n"
            "sudo python3 sentinelbi_sensor.py --self-test\n"
            f"sudo python3 sentinelbi_sensor.py {run}",
        ),
        Snippet(
            "sensor-docker",
            "Docker (Linux host)",
            "shell",
            "# NET_RAW lets it read packets, NET_ADMIN lets it enlarge the capture buffer.\n"
            "docker run --rm --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN python:3.12-slim sh -c \\\n"
            f"  \"python -c \\\"import urllib.request as u; u.urlretrieve('{url}', '/tmp/s.py')\\\" "
            f'&& python /tmp/s.py {run}"',
        ),
        Snippet(
            "sensor-demo",
            "Try it without admin rights",
            "shell",
            "# From the project folder: replay the bundled demo capture (synthetic traffic), mapped onto\n"
            "# one of your addresses, to see the dashboards and reports fill. Nothing is captured.\n"
            "python sensor/sentinelbi_sensor.py --read-pcap data/samples/sensor_demo.pcap --shift-to-now \\\n"
            f"  --map-ip 10.20.0.5={_demo_host(cidr)} --api-url {api} --api-key {key}",
        ),
    ]
    return snippets
