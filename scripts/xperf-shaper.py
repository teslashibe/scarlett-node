#!/usr/bin/env python3
"""Loopback TCP relay for reproducible simulated verifier-link profiles.

TLS passes unchanged to the verifier. This relay never terminates TLS, inspects
application data, or logs payloads. It rejects a non-TLS initial record.
"""
import argparse
import asyncio
import contextlib
import ipaddress
import json
import os
import pathlib
import signal
import time

PROFILES = {"simulated-rtt0": 0, "simulated-rtt20": .010,
            "simulated-rtt80": .040, "simulated-rtt160": .080}
CHUNK = 16384
QUEUE_CHUNKS = 32
IDLE_SECONDS = 330


def endpoint(value, loopback=False):
    if value.startswith("["):
        host, port = value[1:].split("]:", 1)
    else:
        host, port = value.rsplit(":", 1)
    if not host or any(c in host for c in "/@ \r\n\t"):
        raise ValueError("invalid endpoint")
    port = int(port)
    if not 0 <= port <= 65535 or not loopback and port == 0:
        raise ValueError("invalid port")
    if loopback and not ipaddress.ip_address(host).is_loopback:
        raise ValueError("listener must be literal loopback")
    return host, port


def private_json(path, value):
    # Never follow or overwrite an existing path.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, allow_nan=False)
        stream.write("\n")


class Schedule:
    """Reserve aggregate serialization time; propagation never accumulates."""
    def __init__(self, delay, bandwidth):
        self.delay, self.bandwidth, self.next_serialized = delay, bandwidth, 0.0

    def release_at(self, received_at, size):
        if not self.bandwidth:
            return received_at + self.delay
        self.next_serialized = max(received_at, self.next_serialized) + size / self.bandwidth
        return self.next_serialized + self.delay


class Shaper:
    def __init__(self, upstream, profile, bandwidth, max_connections=4):
        self.upstream, self.profile, self.bandwidth = upstream, profile, bandwidth
        self.max_connections = max_connections
        self.schedule = {side: Schedule(PROFILES[profile], bandwidth) for side in ("upload", "download")}
        self.stats = {"schema": 1, "topology": "simulated_loopback_tcp_tls",
                      "profile": profile, "simulated_one_way_delay_ms": round(PROFILES[profile] * 1000),
                      "bandwidth_bytes_second_per_direction": bandwidth,
                      "connections_accepted": 0, "connections_rejected": 0,
                      "connections_completed": 0, "connection_errors": 0,
                      "upload_bytes": 0, "download_bytes": 0,
                      "peak_connections": 0, "peak_queued_bytes": 0,
                      "queue_bound_bytes_per_direction_connection": (QUEUE_CHUNKS + 2) * CHUNK,
                      "max_connections": max_connections, "tls_terminated": False}
        self.active, self.queued, self.tasks = 0, 0, set()

    async def pipe(self, source, destination, direction, initial=b""):
        queue = asyncio.Queue(QUEUE_CHUNKS)
        pending_bytes = 0
        destination.transport.set_write_buffer_limits(high=CHUNK, low=CHUNK // 2)

        async def read():
            nonlocal pending_bytes
            chunk = initial
            while True:
                if not chunk:
                    chunk = await asyncio.wait_for(source.read(CHUNK), IDLE_SECONDS)
                if not chunk:
                    await queue.put(None)
                    return
                release = self.schedule[direction].release_at(asyncio.get_running_loop().time(), len(chunk))
                # Includes the blocked reader's pending chunk in the memory bound.
                pending_bytes += len(chunk)
                self.queued += len(chunk)
                self.stats["peak_queued_bytes"] = max(self.stats["peak_queued_bytes"], self.queued)
                await queue.put((release, chunk))
                chunk = b""

        async def write():
            nonlocal pending_bytes
            while True:
                item = await queue.get()
                if item is None:
                    if destination.can_write_eof():
                        destination.write_eof()
                        await asyncio.wait_for(destination.drain(), IDLE_SECONDS)
                    return
                release, chunk = item
                await asyncio.sleep(max(0, release - asyncio.get_running_loop().time()))
                destination.write(chunk)
                await asyncio.wait_for(destination.drain(), IDLE_SECONDS)
                self.stats[direction + "_bytes"] += len(chunk)
                self.queued -= len(chunk)
                pending_bytes -= len(chunk)

        tasks = [asyncio.create_task(read()), asyncio.create_task(write())]
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            self.queued -= pending_bytes

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        upstream_writer = None
        admitted = False
        try:
            if self.active >= self.max_connections:
                self.stats["connections_rejected"] += 1
                return
            self.active += 1
            admitted = True
            self.stats["connections_accepted"] += 1
            self.stats["peak_connections"] = max(self.stats["peak_connections"], self.active)
            initial = await asyncio.wait_for(reader.readexactly(5), 10)
            # TLS handshake record and valid legacy record version. Credentials
            # cannot enter a plaintext upstream connection through this relay.
            if initial[0] != 22 or initial[1] != 3 or initial[2] not in (1, 2, 3) or not 0 < int.from_bytes(initial[3:], "big") <= CHUNK + 2048:
                raise ValueError("TLS required")
            upstream_reader, upstream_writer = await asyncio.wait_for(asyncio.open_connection(*self.upstream, limit=CHUNK * 2), 10)
            async with asyncio.TaskGroup() as group:
                group.create_task(self.pipe(reader, upstream_writer, "upload", initial))
                group.create_task(self.pipe(upstream_reader, writer, "download"))
            self.stats["connections_completed"] += 1
        except (Exception, asyncio.CancelledError):
            self.stats["connection_errors"] += 1
        finally:
            if admitted:
                self.active -= 1
                if self.active == 0:
                    for schedule in self.schedule.values():
                        schedule.next_serialized = 0
            for stream in (upstream_writer, writer):
                if stream is not None:
                    stream.close()
                    with contextlib.suppress(Exception, asyncio.CancelledError):
                        await asyncio.wait_for(stream.wait_closed(), 5)
            self.tasks.discard(task)

    async def stop(self):
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def serve(args):
    relay = Shaper(endpoint(args.upstream), args.profile, args.bandwidth, args.max_connections)
    host, port = endpoint(args.listen, loopback=True)
    server = await asyncio.start_server(relay.handle, host, port, limit=CHUNK * 2)
    address = server.sockets[0].getsockname()
    private_json(args.ready, {"schema": 1, "listen": f"[{address[0]}]:{address[1]}" if ":" in address[0] else f"{address[0]}:{address[1]}",
                              "topology": "simulated_loopback_tcp_tls", "profile": args.profile,
                              "simulated_one_way_delay_ms": round(PROFILES[args.profile] * 1000),
                              "bandwidth_bytes_second": args.bandwidth})
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    started = time.monotonic()
    await stop.wait()
    server.close()
    await server.wait_closed()
    await relay.stop()
    relay.stats["elapsed_seconds"] = time.monotonic() - started
    private_json(args.stats, relay.stats)


def self_test():
    # Splitting one burst does not multiply propagation delay. Ordering and
    # serialization share a deterministic clock, independent of OS scheduling.
    schedule = Schedule(.040, 0)
    assert all(schedule.release_at(10, CHUNK) == 10.040 for _ in range(100))
    schedule = Schedule(.040, 1000)
    assert abs(schedule.release_at(10, 100) - 10.140) < 1e-9
    assert abs(schedule.release_at(10, 100) - 10.240) < 1e-9
    assert abs(schedule.release_at(11, 100) - 11.140) < 1e-9
    try:
        endpoint("0.0.0.0:7047", loopback=True)
    except ValueError:
        pass
    else:
        raise AssertionError("non-loopback bind accepted")
    print('{"offline_shaper_schedule_tests_passed":true}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--upstream")
    parser.add_argument("--listen", default="127.0.0.1:0")
    parser.add_argument("--profile", choices=PROFILES, default="simulated-rtt0")
    parser.add_argument("--bandwidth", type=int, default=0)
    parser.add_argument("--max-connections", type=int, default=4)
    parser.add_argument("--ready", type=pathlib.Path)
    parser.add_argument("--stats", type=pathlib.Path)
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.upstream or not args.ready or not args.stats or not 0 <= args.bandwidth <= 1000000000 or not 1 <= args.max_connections <= 4:
        parser.error("bounded upstream, output and capacity configuration required")
    asyncio.run(serve(args))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError):
        raise SystemExit("shaper configuration or transport failed")
