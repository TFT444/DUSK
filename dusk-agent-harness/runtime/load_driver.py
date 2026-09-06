"""Concurrent load driver for mixed clean and poisoned scenarios."""

from __future__ import annotations

import argparse
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from harness import run_scenario


@dataclass
class LoadResult:
    latencies_ms: list[float] = field(default_factory=list)
    verdicts: dict[str, int] = field(default_factory=dict)
    errors: int = 0

    def record(self, verdict: str | None, latency_ms: float) -> None:
        self.latencies_ms.append(latency_ms)
        if verdict is None:
            self.errors += 1
        else:
            self.verdicts[verdict] = self.verdicts.get(verdict, 0) + 1

    def percentile(self, p: float) -> float:
        if not self.latencies_ms:
            return 0.0
        ordered = sorted(self.latencies_ms)
        index = min(int(len(ordered) * p), len(ordered) - 1)
        return ordered[index]


def _one_request(agent_id: str, poisoned_ratio: float) -> tuple[str | None, float]:
    scenario = "poisoned" if random.random() < poisoned_ratio else "clean"  # noqa: S311
    start = time.monotonic()
    try:
        result = run_scenario(agent_id, scenario)
        verdict: str | None = str(result["verdict"])
    except Exception:  # noqa: BLE001
        verdict = None
    latency_ms = (time.monotonic() - start) * 1000
    return verdict, latency_ms


def run_load(concurrency: int, total: int, poisoned_ratio: float) -> LoadResult:
    """Fire ``total`` requests at up to ``concurrency`` in flight at once."""
    result = LoadResult()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [
            pool.submit(_one_request, f"load-agent-{i % concurrency}", poisoned_ratio)
            for i in range(total)
        ]
        for future in as_completed(futures):
            verdict, latency_ms = future.result()
            result.record(verdict, latency_ms)
    return result


def check_latency_limits(
    result: LoadResult, *, p50_limit_ms: float, p95_limit_ms: float
) -> str | None:
    """Return a failure message if p50 or p95 exceeds the given limits, else None."""
    if not result.latencies_ms:
        return None
    p50 = result.percentile(0.50)
    p95 = result.percentile(0.95)
    if p50 > p50_limit_ms:
        return f"p50 {p50:.1f} ms exceeds limit of {p50_limit_ms:.1f} ms"
    if p95 > p95_limit_ms:
        return f"p95 {p95:.1f} ms exceeds limit of {p95_limit_ms:.1f} ms"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="DUSK runtime load driver")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrent requests.")
    parser.add_argument("--total", type=int, default=100, help="Total requests to send.")
    parser.add_argument(
        "--poisoned-ratio",
        type=float,
        default=0.2,
        help="Fraction of requests using the poisoned scenario (default 0.2).",
    )
    parser.add_argument(
        "--p50-limit-ms",
        type=float,
        default=0,
        help="Fail if p50 latency exceeds this value in ms (0 = no limit).",
    )
    parser.add_argument(
        "--p95-limit-ms",
        type=float,
        default=0,
        help="Fail if p95 latency exceeds this value in ms (0 = no limit).",
    )
    args = parser.parse_args()

    print(
        f"Firing {args.total} requests, concurrency={args.concurrency}, "
        f"poisoned_ratio={args.poisoned_ratio}..."
    )
    result = run_load(args.concurrency, args.total, args.poisoned_ratio)

    print(f"\nverdicts: {result.verdicts}")
    print(f"errors:   {result.errors}")
    print(f"p50:      {result.percentile(0.50):.1f} ms")
    print(f"p95:      {result.percentile(0.95):.1f} ms")
    print(f"p99:      {result.percentile(0.99):.1f} ms")
    print(f"max:      {max(result.latencies_ms, default=0.0):.1f} ms")

    if result.errors:
        return 1

    if args.p50_limit_ms > 0 or args.p95_limit_ms > 0:
        failure = check_latency_limits(
            result,
            p50_limit_ms=args.p50_limit_ms or float("inf"),
            p95_limit_ms=args.p95_limit_ms or float("inf"),
        )
        if failure:
            print(f"\nFAIL latency: {failure}")
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
