#!/usr/bin/env python3
"""Offline fixture tests for the TLS-preserving loopback transport shaper."""
import asyncio
import contextlib
import importlib.util
import pathlib
import ssl
import subprocess
import tempfile
import sys
import unittest

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("shaper", pathlib.Path(__file__).with_name("xperf-shaper.py"))
shaper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shaper)


class ShaperTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.servers = []
        self.relays = []

    async def asyncTearDown(self):
        for server in self.servers:
            server.close()
            await server.wait_closed()
        for relay in self.relays:
            await relay.stop()
            self.assertEqual(relay.active, 0)
            self.assertEqual(relay.queued, 0)

    async def start(self, upstream_handler, profile="simulated-rtt0", bandwidth=0, ssl_context=None, upstream=None):
        if upstream is None:
            server = await asyncio.start_server(upstream_handler, "127.0.0.1", 0, ssl=ssl_context)
            self.servers.append(server)
            upstream = ("127.0.0.1", server.sockets[0].getsockname()[1])
        relay = shaper.Shaper(upstream, profile, bandwidth)
        server = await asyncio.start_server(relay.handle, "127.0.0.1", 0, limit=shaper.CHUNK * 2)
        self.servers.append(server)
        self.relays.append(relay)
        return relay, server.sockets[0].getsockname()[1]

    async def settle(self, relay):
        for _ in range(200):
            if not relay.active:
                return
            await asyncio.sleep(.005)
        self.fail("relay did not drain")

    async def test_order_delay_pipeline_bandwidth_and_half_close(self):
        payload = b"\x16\x03\x03\x00\x10" + bytes(range(256)) * 512
        received = []

        async def upstream(reader, writer):
            data = await reader.read()
            received.append(data)
            # Respond only after client half-close. Reverse bytes prove that
            # the download stream still survives an upload EOF.
            writer.write(data[::-1])
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        relay, port = await self.start(upstream, "simulated-rtt80", 2_000_000)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        started = asyncio.get_running_loop().time()
        writer.write(payload)
        await writer.drain()
        writer.write_eof()
        response = await reader.read()
        elapsed = asyncio.get_running_loop().time() - started
        writer.close()
        await writer.wait_closed()
        await self.settle(relay)
        self.assertEqual(received, [payload])
        self.assertEqual(response, payload[::-1])
        self.assertGreaterEqual(elapsed, .075)
        # A sleep-per-chunk implementation exceeds this loose bound. Exact
        # delay math is tested separately without a scheduler or wall clock.
        self.assertLess(elapsed, .8)
        self.assertEqual(relay.stats["upload_bytes"], len(payload))
        self.assertEqual(relay.stats["download_bytes"], len(payload))
        self.assertEqual(relay.stats["connections_completed"], 1)
        self.assertLessEqual(relay.stats["peak_queued_bytes"], 2 * (shaper.QUEUE_CHUNKS + 2) * shaper.CHUNK)

    async def test_plaintext_rejection_and_connection_capacity_recovery(self):
        connected = asyncio.Event()
        release = asyncio.Event()

        async def upstream(reader, writer):
            await reader.readexactly(5)
            connected.set()
            await release.wait()
            writer.close()
            await writer.wait_closed()

        relay, port = await self.start(upstream)
        relay.max_connections = 1
        first_r, first_w = await asyncio.open_connection("127.0.0.1", port)
        first_w.write(b"\x16\x03\x03\x00\x10")
        await first_w.drain()
        await connected.wait()
        second_r, second_w = await asyncio.open_connection("127.0.0.1", port)
        self.assertEqual(await asyncio.wait_for(second_r.read(), 1), b"")
        second_w.close()
        await second_w.wait_closed()
        release.set()
        first_w.write_eof()
        self.assertEqual(await first_r.read(), b"")
        first_w.close()
        await first_w.wait_closed()
        await self.settle(relay)
        plain_r, plain_w = await asyncio.open_connection("127.0.0.1", port)
        plain_w.write(b"GET / plaintext-secret")
        await plain_w.drain()
        with contextlib.suppress(ConnectionResetError):
            self.assertEqual(await asyncio.wait_for(plain_r.read(), 1), b"")
        plain_w.close()
        with contextlib.suppress(ConnectionResetError):
            await plain_w.wait_closed()
        await self.settle(relay)
        self.assertEqual(relay.stats["connections_rejected"], 1)
        self.assertEqual(relay.stats["connection_errors"], 1)
        self.assertEqual(relay.stats["peak_connections"], 1)

    async def test_valid_ca_tls_identity_and_ciphertext_counters(self):
        with tempfile.TemporaryDirectory() as fixture:
            root = pathlib.Path(fixture)
            cert, key = root / "fixture.pem", root / "fixture.key"
            # This disposable synthetic certificate contains no account or
            # verifier identity and is trusted only by this test client.
            await asyncio.to_thread(subprocess.run, ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-keyout", str(key), "-out", str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(cert, key)
            client_context = ssl.create_default_context(cafile=str(cert))
            payload = b"SYNTHETIC-FIXTURE" * 2000

            async def upstream(reader, writer):
                data = await reader.readexactly(len(payload))
                writer.write(data)
                await writer.drain()
                writer.close()
                await writer.wait_closed()

            relay, port = await self.start(upstream, ssl_context=server_context)
            reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=client_context, server_hostname="localhost")
            writer.write(payload)
            await writer.drain()
            self.assertEqual(await reader.readexactly(len(payload)), payload)
            writer.close()
            await writer.wait_closed()
            await self.settle(relay)
            self.assertGreater(relay.stats["upload_bytes"], len(payload))
            self.assertGreater(relay.stats["download_bytes"], len(payload))
            loop = asyncio.get_running_loop()
            previous_handler = loop.get_exception_handler()
            def expected_rejection(loop, context):
                if isinstance(context.get("exception"), (ConnectionResetError, ssl.SSLError)):
                    return
                if previous_handler:
                    previous_handler(loop, context)
                else:
                    loop.default_exception_handler(context)
            loop.set_exception_handler(expected_rejection)
            try:
                with self.assertRaises(ssl.SSLCertVerificationError):
                    await asyncio.open_connection("127.0.0.1", port, ssl=client_context, server_hostname="wrong.invalid")
                await self.settle(relay)
                await asyncio.sleep(.01)
            finally:
                loop.set_exception_handler(previous_handler)
            self.assertFalse(relay.stats["tls_terminated"])

    async def test_blocked_stream_memory_bound_and_abort_recovery(self):
        release = asyncio.Event()
        async def upstream(reader, writer):
            await release.wait()
            writer.close()
            await writer.wait_closed()
        relay, port = await self.start(upstream, "simulated-rtt160", 1)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"\x16\x03\x03\x00\x10" + b"F" * (2 << 20))
        await writer.drain()
        for _ in range(100):
            if relay.stats["peak_queued_bytes"] >= shaper.QUEUE_CHUNKS * shaper.CHUNK:
                break
            await asyncio.sleep(.005)
        self.assertGreaterEqual(relay.stats["peak_queued_bytes"], shaper.QUEUE_CHUNKS * shaper.CHUNK)
        self.assertLessEqual(relay.stats["peak_queued_bytes"], (shaper.QUEUE_CHUNKS + 2) * shaper.CHUNK)
        await relay.stop()
        self.assertEqual(relay.queued, 0)
        self.assertEqual(relay.active, 0)
        self.assertEqual(relay.schedule["upload"].next_serialized, 0)
        release.set()
        writer.close()
        with contextlib.suppress(ConnectionResetError):
            await writer.wait_closed()

    async def test_unavailable_upstream_releases_capacity(self):
        unused = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        address = ("127.0.0.1", unused.sockets[0].getsockname()[1])
        unused.close()
        await unused.wait_closed()
        relay, port = await self.start(None, upstream=address)
        for _ in range(2):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"\x16\x03\x03\x00\x10")
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")
            writer.close()
            await writer.wait_closed()
            await self.settle(relay)
        self.assertEqual(relay.stats["connection_errors"], 2)
        self.assertEqual(relay.stats["connections_accepted"], 2)


if __name__ == "__main__":
    unittest.main()
