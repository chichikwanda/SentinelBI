"""Setup instructions shown by the onboarding wizard.

An IP address alone gives the platform no visibility (plan section 1), so registering a source
must tell the user how traffic will actually reach us: collector address, API key, and
copy-paste router configuration.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.config import Settings
from app.core.enums import SourceMethod


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


def build_setup_info(method: SourceMethod, api_key: str, settings: Settings) -> SetupInfo:
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
    if method in (SourceMethod.HTTP, SourceMethod.SENSOR):
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
        snippets.append(
            Snippet(
                "sensor",
                "Sensor container (image not published yet)",
                "shell",
                f"docker run -e PLATFORM_URL={api} -e API_KEY={api_key} \\\n"
                f"  --net=host sentinelbi/sensor",
            )
        )
    return SetupInfo(host, port, api, snippets)
