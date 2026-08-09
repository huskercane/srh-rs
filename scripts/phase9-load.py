#!/usr/bin/env python3
"""Phase 9 bend-not-break acceptance runner (standard library only)."""

from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import json
import math
import os
import statistics
import subprocess
import time
from dataclasses import dataclass


TOKEN = "phase9-load-token"
BODY = b'["GET","load:key"]'


@dataclass(frozen=True)
class Sample:
    at: float
    status: int
    latency_ms: float
    retry_after: str | None
    body: bytes


def percentile(values: list[float], quantile: float) -> float:
    assert values, "cannot calculate a percentile of an empty sample"
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * quantile) - 1)]


async def request(
    host: str,
    port: int,
    body: bytes = BODY,
    path: str = "/",
    timeout: float = 6.0,
) -> Sample:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    try:
        return await request_on_connection(reader, writer, host, body, path, timeout, True)
    finally:
        writer.close()
        await writer.wait_closed()


async def request_on_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host: str,
    body: bytes = BODY,
    path: str = "/",
    timeout: float = 6.0,
    close: bool = False,
) -> Sample:
    started = time.monotonic()
    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Authorization: Bearer {TOKEN}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: {'close' if close else 'keep-alive'}\r\n\r\n"
    ).encode()
    writer.write(headers + body)
    await writer.drain()
    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout)
    lines = head.decode("latin1").split("\r\n")
    status = int(lines[0].split()[1])
    response_headers = {
        key.strip().lower(): value.strip()
        for line in lines[1:]
        if ":" in line
        for key, value in [line.split(":", 1)]
    }
    length = int(response_headers.get("content-length", "0"))
    response_body = await asyncio.wait_for(reader.readexactly(length), timeout)
    return Sample(
        at=started,
        status=status,
        latency_ms=(time.monotonic() - started) * 1000,
        retry_after=response_headers.get("retry-after"),
        body=response_body,
    )


async def get(host: str, port: int, path: str) -> tuple[int, bytes]:
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
    )
    await writer.drain()
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
        lines = head.decode("latin1").split("\r\n")
        status = int(lines[0].split()[1])
        length = next(
            (
                int(line.split(":", 1)[1])
                for line in lines[1:]
                if line.lower().startswith("content-length:")
            ),
            0,
        )
        return status, await asyncio.wait_for(reader.readexactly(length), 2)
    finally:
        writer.close()
        await writer.wait_closed()


async def load_shard(
    host: str, port: int, concurrency: int, duration: float
) -> tuple[list[Sample], list[str]]:
    samples: list[Sample] = []
    errors: list[str] = []
    deadline = time.monotonic() + duration

    async def worker() -> None:
        reader: asyncio.StreamReader | None = None
        writer: asyncio.StreamWriter | None = None
        while time.monotonic() < deadline:
            try:
                if writer is None or writer.is_closing():
                    reader, writer = await asyncio.open_connection(host, port)
                assert reader is not None
                samples.append(await request_on_connection(reader, writer, host))
            except Exception as error:  # A reset is an acceptance failure, not a runner crash.
                errors.append(repr(error))
                if writer is not None:
                    writer.close()
                    await writer.wait_closed()
                reader = None
                writer = None
        if writer is not None:
            writer.close()
            await writer.wait_closed()

    await asyncio.gather(*(worker() for _ in range(concurrency)))
    return samples, errors


def run_load_shard(
    host: str, port: int, concurrency: int, duration: float
) -> tuple[list[Sample], list[str]]:
    return asyncio.run(load_shard(host, port, concurrency, duration))


async def load(
    host: str, port: int, concurrency: int, duration: float
) -> tuple[list[Sample], list[str]]:
    # Several small event loops model a native load generator more faithfully than one Python
    # loop dispatching a large response wave. Otherwise client-side callback delay is counted as
    # proxy latency and can exceed the sub-10ms shed budget even when the server responds at once.
    shards = min(4, concurrency)
    sizes = [concurrency // shards + (index < concurrency % shards) for index in range(shards)]
    loop = asyncio.get_running_loop()
    with concurrent.futures.ProcessPoolExecutor(max_workers=shards) as executor:
        batches = await asyncio.gather(
            *(
                loop.run_in_executor(executor, run_load_shard, host, port, size, duration)
                for size in sizes
            )
        )
    samples = [sample for batch, _ in batches for sample in batch]
    errors = [error for _, batch_errors in batches for error in batch_errors]
    return samples, errors


def container_pid(name: str) -> int:
    output = subprocess.check_output(
        ["docker", "inspect", "--format", "{{.State.Pid}}", name], text=True
    )
    return int(output.strip())


def rss_bytes(pid: int) -> int:
    with open(f"/proc/{pid}/status", encoding="ascii") as status:
        for line in status:
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    raise AssertionError(f"VmRSS missing for pid {pid}")


async def health_and_rss_monitor(
    host: str, http_port: int, metrics_port: int, pid: int, stop: asyncio.Event
) -> tuple[list[int], list[str]]:
    rss: list[int] = []
    errors: list[str] = []
    while not stop.is_set():
        rss.append(rss_bytes(pid))
        try:
            health, _ = await get(host, http_port, "/health")
            metrics, _ = await get(host, metrics_port, "/metrics")
            if health != 200 or metrics != 200:
                errors.append(f"health={health} metrics={metrics}")
        except Exception as error:
            errors.append(repr(error))
        try:
            await asyncio.wait_for(stop.wait(), 0.25)
        except TimeoutError:
            pass
    return rss, errors


def validate_responses(samples: list[Sample], errors: list[str]) -> None:
    assert not errors, f"connection failures/resets: {errors[:5]}"
    unexpected = [sample.status for sample in samples if sample.status not in (200, 503)]
    assert not unexpected, f"unexpected statuses: {unexpected[:20]}"
    missing_retry = [sample for sample in samples if sample.status == 503 and not sample.retry_after]
    assert not missing_retry, "a 503 response omitted Retry-After"


async def unloaded_p99(host: str, port: int) -> float:
    async def worker() -> list[Sample]:
        reader, writer = await asyncio.open_connection(host, port)
        try:
            return [await request_on_connection(reader, writer, host) for _ in range(25)]
        finally:
            writer.close()
            await writer.wait_closed()

    # Four clients match the four Redis permits without queueing or shedding; the overload
    # profile drives exactly four times this measured capacity.
    samples = [sample for batch in await asyncio.gather(*(worker() for _ in range(4))) for sample in batch]
    assert all(sample.status == 200 for sample in samples)
    return percentile([sample.latency_ms for sample in samples], 0.99)


async def assert_recovered(host: str, port: int) -> None:
    expected = json.dumps({"result": "phase9-value"}, separators=(",", ":")).encode()
    for _ in range(100):
        sample = await request(host, port)
        assert sample.status == 200 and sample.body == expected, sample


async def overload(args: argparse.Namespace) -> None:
    seed = await request(args.host, args.http_port, b'["SET","load:key","phase9-value"]')
    assert seed.status == 200
    baseline_p99 = await unloaded_p99(args.host, args.http_port)
    # Prime the configured connection envelope before taking an allocator baseline. The gate is
    # about growth during sustained load, not the one-time cost of creating Hyper connection
    # tasks on a freshly started process.
    if args.warm_duration > 0:
        warm_samples, warm_errors = await load(
            args.host,
            args.http_port,
            args.concurrency,
            min(args.warm_duration, args.duration),
        )
        validate_responses(warm_samples, warm_errors)
        await asyncio.sleep(0.25)
    pid = container_pid(args.proxy_container)
    baseline_rss = rss_bytes(pid)
    stop = asyncio.Event()
    monitor = asyncio.create_task(
        health_and_rss_monitor(args.host, args.http_port, args.metrics_port, pid, stop)
    )
    samples, errors = await load(args.host, args.http_port, args.concurrency, args.duration)
    stop.set()
    rss, monitor_errors = await monitor
    validate_responses(samples, errors)
    assert not monitor_errors, f"observability endpoints failed: {monitor_errors[:5]}"
    accepted = [sample.latency_ms for sample in samples if sample.status == 200]
    rejected = [sample.latency_ms for sample in samples if sample.status == 503]
    assert accepted and rejected, "overload must produce both accepted and shed requests"
    accepted_p99 = percentile(accepted, 0.99)
    rejected_p99 = percentile(rejected, 0.99)
    assert accepted_p99 < baseline_p99 * 5, (
        f"accepted p99 {accepted_p99:.2f}ms exceeded 5x baseline {baseline_p99:.2f}ms"
    )
    assert rejected_p99 < 10, f"shed p99 {rejected_p99:.2f}ms was not below 10ms"
    peak_rss = max(rss)
    assert peak_rss < baseline_rss * 1.20, (
        f"RSS grew by 20% or more: baseline={baseline_rss} peak={peak_rss}"
    )
    await asyncio.sleep(2)
    recovered_rss = rss_bytes(pid)
    assert recovered_rss < baseline_rss * 1.20, (
        f"RSS did not return to its baseline band: baseline={baseline_rss} recovered={recovered_rss}"
    )
    await assert_recovered(args.host, args.http_port)
    print(f"overload: {len(samples)} responses; baseline p99={baseline_p99:.2f}ms")


def signal_container(name: str, signal: str) -> None:
    subprocess.run(["docker", "kill", "--signal", signal, name], check=True, capture_output=True)


async def backend_death(args: argparse.Namespace) -> None:
    seed = await request(args.host, args.http_port, b'["SET","load:key","phase9-value"]')
    assert seed.status == 200
    started_at = subprocess.check_output(
        ["docker", "inspect", "--format", "{{.State.StartedAt}}", args.proxy_container],
        text=True,
    ).strip()

    async def disrupt() -> None:
        await asyncio.sleep(args.stop_at)
        signal_container(args.redis_container, "STOP")
        await asyncio.sleep(args.continue_at - args.stop_at)
        signal_container(args.redis_container, "CONT")

    origin = time.monotonic()
    disruption = asyncio.create_task(disrupt())
    samples, errors = await load(args.host, args.http_port, args.concurrency, args.duration)
    await disruption
    validate_responses(samples, errors)
    relative = [
        Sample(sample.at - origin, sample.status, sample.latency_ms, sample.retry_after, sample.body)
        for sample in samples
    ]
    fast_start = min(args.stop_at + 5, args.continue_at - 1)
    fast_window = [
        sample.latency_ms for sample in relative if fast_start <= sample.at < args.continue_at
    ]
    fast_p99 = percentile(fast_window, 0.99) if fast_window else float("inf")
    assert fast_window and fast_p99 < 10, (
        f"breaker did not become fast within 5s: p99={fast_p99:.2f}ms"
    )
    pre_start = min(5.0, max(0.0, args.stop_at - 3))
    pre_end = args.stop_at - 1
    before = [
        sample for sample in relative if pre_start <= sample.at < pre_end and sample.status == 200
    ]
    recovery_start = min(args.continue_at + 5, args.duration - 2)
    after = [sample for sample in relative if recovery_start <= sample.at and sample.status == 200]
    assert before, "no healthy baseline responses were measured before Redis stopped"
    before_rate = len(before) / max(1.0, pre_end - pre_start)
    after_rate = len(after) / max(1.0, args.duration - recovery_start)
    assert after_rate >= before_rate * 0.8, "200-rate did not recover within 10s"
    ended_at = subprocess.check_output(
        ["docker", "inspect", "--format", "{{.State.StartedAt}}", args.proxy_container],
        text=True,
    ).strip()
    assert ended_at == started_at, "proxy restarted during backend recovery"
    await assert_recovered(args.host, args.http_port)
    print(f"backend death: pre={before_rate:.1f}/s recovered={after_rate:.1f}/s")


async def slow_request(host: str, port: int) -> Sample:
    started = time.monotonic()
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(
        (
            f"POST / HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {TOKEN}\r\n"
            "Content-Type: application/json\r\nContent-Length: 100\r\nConnection: close\r\n\r\n["
        ).encode()
    )
    await writer.drain()
    async def trickle() -> None:
        for _ in range(4):
            await asyncio.sleep(1)
            try:
                writer.write(b" ")
                await writer.drain()
            except (BrokenPipeError, ConnectionResetError):
                break

    trickler = asyncio.create_task(trickle())
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 4)
        lines = head.decode("latin1").split("\r\n")
        return Sample(
            time.monotonic(),
            int(lines[0].split()[1]),
            (time.monotonic() - started) * 1000,
            None,
            b"",
        )
    finally:
        trickler.cancel()
        await asyncio.gather(trickler, return_exceptions=True)
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionResetError:
            pass


async def slow_clients(args: argparse.Namespace) -> None:
    baseline = await unloaded_p99(args.host, args.http_port)

    async def attack_wave(check_permits: bool) -> list[Sample]:
        attacks = [
            asyncio.create_task(slow_request(args.host, args.http_port)) for _ in range(64)
        ]
        gauge_values: list[float] = []
        while any(not attack.done() for attack in attacks):
            if check_permits:
                status, body = await get(args.host, args.metrics_port, "/metrics")
                assert status == 200
                for line in body.decode().splitlines():
                    if line.startswith('srh_pool_permits_in_use{pool="load"}'):
                        gauge_values.append(float(line.rsplit(" ", 1)[1]))
            await asyncio.sleep(0.1)
        results = await asyncio.gather(*attacks)
        if check_permits:
            assert gauge_values and max(gauge_values) == 0, (
                "slow bodies reached Redis pool acquisition"
            )
        return results

    attack_results = await attack_wave(True)
    concurrent_attacks = asyncio.create_task(attack_wave(False))
    await asyncio.sleep(0.2)
    normal, errors = await load(args.host, args.http_port, 16, 4)
    attack_results.extend(await concurrent_attacks)
    assert all(sample.status == 408 for sample in attack_results), attack_results
    assert all(1500 <= sample.latency_ms <= 3500 for sample in attack_results), attack_results
    validate_responses(normal, errors)
    accepted = [sample.latency_ms for sample in normal if sample.status == 200]
    assert accepted and percentile(accepted, 0.99) < baseline * 2, "normal p99 exceeded 2x baseline"
    print(f"slow clients: 128 timed out across two stages; normal baseline p99={baseline:.2f}ms")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("profile", choices=("overload", "backend-death", "slow-client"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--http-port", type=int, default=18080)
    parser.add_argument("--metrics-port", type=int, default=19090)
    parser.add_argument("--proxy-container", default="srh-phase9")
    parser.add_argument("--redis-container", default="redis-phase9")
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--duration", type=float, default=float(os.getenv("PHASE9_DURATION", "60")))
    parser.add_argument("--warm-duration", type=float, default=15)
    parser.add_argument("--stop-at", type=float, default=20)
    parser.add_argument("--continue-at", type=float, default=40)
    return parser.parse_args()


async def main() -> None:
    args = parse_args()
    if args.profile == "overload":
        await overload(args)
    elif args.profile == "backend-death":
        await backend_death(args)
    else:
        await slow_clients(args)


if __name__ == "__main__":
    asyncio.run(main())
