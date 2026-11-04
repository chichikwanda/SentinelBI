"""Who made a network card, from the first three bytes of its MAC address.

``app/data/oui.tsv.gz`` is the IEEE public OUI registry (about 40,000 vendor prefixes), one
``prefix<TAB>name`` line each, first line of the registered name only. A modern phone or laptop
often uses a random (locally administered) MAC for privacy: it has no vendor, and is reported as
such instead of guessed.
"""

from __future__ import annotations

import gzip
from functools import lru_cache
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data" / "oui.tsv.gz"
RANDOMISED = "Randomised address (privacy feature)"


@lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    table: dict[str, str] = {}
    try:
        with gzip.open(DATA, "rt", encoding="utf-8") as f:
            for line in f:
                prefix, _, name = line.rstrip("\n").partition("\t")
                if name:
                    table[prefix] = name
    except OSError:
        return {}  # no table shipped: the vendor column is simply empty
    return table


def vendor_for(mac: str | None) -> str | None:
    """The registered vendor of ``mac``, ``RANDOMISED`` for a locally administered address,
    or None when it is unknown."""
    if not mac:
        return None
    digits = "".join(c for c in mac.lower() if c in "0123456789abcdef")
    if len(digits) < 6:
        return None
    if int(digits[:2], 16) & 0x02:  # the "locally administered" bit: set by the device itself
        return RANDOMISED
    return _table().get(digits[:6])
