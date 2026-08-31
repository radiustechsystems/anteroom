#!/usr/bin/env python3
"""Refresh Anteroom's embedded crawler IP ranges."""

import argparse
import ipaddress
import json
import pathlib
import sys
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCES = {
    "googlebot": (
        "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
        ROOT / "internal/crawler/google_common_crawlers.json",
    ),
    "bingbot": (
        "https://www.bing.com/toolbox/bingbot.json",
        ROOT / "internal/crawler/bingbot.json",
    ),
    "ccbot": (
        "https://index.commoncrawl.org/ccbot.json",
        ROOT / "internal/crawler/ccbot.json",
    ),
}
MAX_BYTES = 1 << 20


def download(name: str, source: str) -> bytes:
    request = urllib.request.Request(
        source, headers={"User-Agent": "anteroom-range-updater/1"}
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        body = response.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError(f"{name} range document exceeds 1 MiB")
    return body


def normalize(name: str, raw: bytes) -> bytes:
    document = json.loads(raw)
    if not isinstance(document.get("creationTime"), str):
        raise ValueError(f"{name} range document is missing creationTime")
    prefixes = set()
    for item in document.get("prefixes", []):
        if not isinstance(item, dict) or len(item) != 1:
            raise ValueError(f"unexpected {name} prefix entry: {item!r}")
        key, value = next(iter(item.items()))
        if key not in ("ipv4Prefix", "ipv6Prefix"):
            raise ValueError(f"unexpected {name} prefix key: {key!r}")
        network = ipaddress.ip_network(value, strict=True)
        expected = "ipv4Prefix" if network.version == 4 else "ipv6Prefix"
        if key != expected:
            raise ValueError(f"{value!r} is under {key}, want {expected}")
        prefixes.add(network)
    if not prefixes:
        raise ValueError(f"{name} range document contains no prefixes")
    ordered = sorted(
        prefixes,
        key=lambda network: (
            network.version,
            int(network.network_address),
            network.prefixlen,
        ),
    )
    normalized = {
        "creationTime": document["creationTime"],
        "prefixes": [
            {
                "ipv4Prefix" if network.version == 4 else "ipv6Prefix": str(
                    network
                )
            }
            for network in ordered
        ],
    }
    return (json.dumps(normalized, indent=2) + "\n").encode()


def ranges(raw: bytes):
    return json.loads(raw).get("prefixes")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="fail if an embedded snapshot is stale"
    )
    args = parser.parse_args()

    # Fetch and validate every source before changing any file.
    updates = {
        name: (source, target, normalize(name, download(name, source)))
        for name, (source, target) in SOURCES.items()
    }
    stale = []
    for name, (source, target, updated) in updates.items():
        current = target.read_bytes() if target.exists() else b""
        if current and ranges(current) == ranges(updated):
            print(f"{target} is current")
            continue
        stale.append((name, source, target, updated))

    if args.check and stale:
        for _, _, target, _ in stale:
            print(
                f"{target} is stale; run {pathlib.Path(__file__).name}",
                file=sys.stderr,
            )
        return 1
    for _, source, target, updated in stale:
        target.write_bytes(updated)
        print(f"updated {target} from {source}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
