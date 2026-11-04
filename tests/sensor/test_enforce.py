"""Enforcing the quarantine in this machine's firewall: opt-in, reversible, and never self-harming."""

from __future__ import annotations

import threading
import types
from typing import Any

import sentinelbi_sensor as s


class FakeFirewall:
    """Stands in for netsh / iptables: records every command and keeps the rules it was given."""

    def __init__(self, windows: bool, fail: bool = False) -> None:
        self.windows, self.fail = windows, fail
        self.commands: list[list[str]] = []
        self.rules: set[str] = set()

    def __call__(self, cmd: list[str]) -> Any:
        self.commands.append(cmd)
        out = ""
        if self.windows:
            if cmd[3] == "show":
                out = "".join(f"Rule Name:                  {r}\n" for r in sorted(self.rules))
            elif cmd[3] == "add" and not self.fail:
                self.rules.add(cmd[5].removeprefix("name="))
            elif cmd[3] == "delete":
                self.rules.discard(cmd[5].removeprefix("name="))
        elif cmd[1] == "-S":
            out = "".join(
                f'-A INPUT -s 1.2.3.4/32 -m comment --comment "{r}" -j DROP\n'
                for r in sorted(self.rules)
            )
        elif "-I" in cmd and not self.fail:
            self.rules.add(cmd[cmd.index("--comment") + 1])
        elif "-D" in cmd:
            self.rules.discard(cmd[cmd.index("--comment") + 1])
        return types.SimpleNamespace(returncode=1 if self.fail else 0, stdout=out)


def make(
    windows: bool, protected: list[str], fail: bool = False
) -> tuple[s.Enforcer, FakeFirewall]:
    fw = FakeFirewall(windows, fail)
    enforcer = s.Enforcer(protected, run=fw)
    enforcer.windows = windows
    return enforcer, fw


def test_it_blocks_what_is_held_and_releases_what_is_not_on_windows() -> None:
    enforcer, fw = make(True, ["192.168.1.6"])
    enforcer.sync(["203.0.113.0/24", "198.51.100.7"])
    assert fw.rules == {
        "SentinelBI quarantine 203.0.113.0/24",
        "SentinelBI quarantine 198.51.100.7",
    }
    adds = [c for c in fw.commands if c[3] == "add"]
    assert len(adds) == 4 and {c[6] for c in adds} == {"dir=in", "dir=out"}
    enforcer.sync(["198.51.100.7"])  # the /24 was released by a person
    assert fw.rules == {"SentinelBI quarantine 198.51.100.7"}
    before = len(fw.commands)
    enforcer.sync(["198.51.100.7"])  # nothing changed: only the rules are read
    assert all(c[3] == "show" for c in fw.commands[before:])


def test_it_uses_tagged_iptables_rules_on_linux() -> None:
    enforcer, fw = make(False, ["10.0.0.2"])
    enforcer.sync(["203.0.113.0/24", "2001:db8::/48"])
    assert fw.rules == {
        "SentinelBI-quarantine:203.0.113.0/24",
        "SentinelBI-quarantine:2001:db8::/48",
    }
    tools = {c[0] for c in fw.commands}
    assert {"iptables", "ip6tables"} <= tools


def test_it_never_blocks_this_machine_its_server_or_its_gateway() -> None:
    enforcer, fw = make(True, ["192.168.1.6", "192.168.1.1", "10.9.9.9"])
    enforcer.sync(["192.168.1.0/24", "192.168.1.1", "10.9.9.9", "not-an-address", "203.0.113.5"])
    assert fw.rules == {"SentinelBI quarantine 203.0.113.5"}
    assert enforcer.refused == {"192.168.1.0/24", "192.168.1.1", "10.9.9.9"}


def test_a_failed_block_is_not_recorded_as_applied() -> None:
    enforcer, fw = make(True, [], fail=True)
    enforcer.sync(["203.0.113.5"])
    assert fw.rules == set() and enforcer.applied == set()


def test_a_server_outage_releases_nothing() -> None:
    enforcer, fw = make(True, [])
    enforcer.sync(["203.0.113.5"])

    class Offline:
        def call(self, *_args: Any, **_kwargs: Any) -> None:
            return None

    s.EnforceLoop(Offline(), threading.Event(), enforcer).once()  # type: ignore[arg-type]
    assert fw.rules == {"SentinelBI quarantine 203.0.113.5"}
