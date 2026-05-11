#!/usr/bin/env python3
"""Generate benign background traffic for DIPS lab evaluation."""
from __future__ import annotations

import argparse
import random
import socket
import time

import requests


def do_http(target: str, port: int, timeout: float) -> None:
    url = f"http://{target}:{port}/"
    try:
        requests.get(url, timeout=timeout)
    except requests.RequestException:
        pass


def do_tcp_probe(target: str, port: int, timeout: float) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
    except OSError:
        pass
    finally:
        sock.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate benign traffic to the production node.")
    parser.add_argument("--target", default="10.0.0.30", help="Target production host IP")
    parser.add_argument("--http-port", type=int, default=80, help="HTTP port")
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH port")
    parser.add_argument("--duration", type=int, default=60, help="Run duration in seconds")
    parser.add_argument("--sleep", type=float, default=0.3, help="Delay between events")
    args = parser.parse_args()

    random.seed(42)
    end_time = time.time() + args.duration

    print(f"Starting benign traffic for {args.duration}s -> {args.target}")
    while time.time() < end_time:
        if random.random() < 0.75:
            do_http(args.target, args.http_port, timeout=1.5)
        else:
            do_tcp_probe(args.target, args.ssh_port, timeout=1.0)
        time.sleep(args.sleep)

    print("Benign traffic generation complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
