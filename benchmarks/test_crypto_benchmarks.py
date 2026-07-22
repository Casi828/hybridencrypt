"""
Benchmark suite for the SPY hybrid encryption pipeline.

Run with:  python -m pytest benchmarks/ -q
Normal test suite (tests/) is unaffected — testpaths in pyproject.toml excludes benchmarks/.

Metrics captured per benchmark:
  - encrypt_latency_s       : wall-clock seconds for stream_encrypt_file
  - encrypt_throughput_mbs  : plaintext MB per second
  - encrypt_peak_memory_b   : tracemalloc peak Python heap bytes during encrypt
  - decrypt_latency_s       : wall-clock seconds for stream_decrypt_file
  - decrypt_throughput_mbs  : plaintext MB per second
  - decrypt_peak_memory_b   : tracemalloc peak Python heap bytes during decrypt
  - output_overhead_b       : ciphertext bytes above plaintext size (container framing)

Statistics over ITERATIONS runs: mean, median, min, max, stdev.
"""

from __future__ import annotations

import os
import statistics
import time
import tracemalloc
from pathlib import Path

import pytest

from spy.file_crypto_engine import stream_decrypt_file, stream_encrypt_file
from spy.key_provider import LocalPemKeyProvider

ITERATIONS = 5

FILE_SIZES = [
    ("1KB",   1 * 1024),
    ("64KB",  64 * 1024),
    ("1MB",   1 * 1024 * 1024),
    ("10MB",  10 * 1024 * 1024),
    ("50MB",  50 * 1024 * 1024),
    ("100MB", 100 * 1024 * 1024),
    ("1GB",   1 * 1024 * 1024 * 1024),
]

CLASSIFICATION_CASES = [
    ("low",    "analyst_low"),
    ("medium", "analyst_med"),
    ("high",   "admin"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _provider() -> LocalPemKeyProvider:
    return LocalPemKeyProvider()


def _stats(values: list[float]) -> dict:
    return {
        "mean":   statistics.mean(values),
        "median": statistics.median(values),
        "min":    min(values),
        "max":    max(values),
        "stdev":  statistics.stdev(values) if len(values) > 1 else 0.0,
    }


def _record(
    results: list,
    *,
    test_name: str,
    size_label: str,
    size_bytes: int,
    method: str,
    classification: str,
    metric: str,
    values: list[float],
    unit: str,
) -> None:
    s = _stats(values)
    results.append({
        "test_name":       test_name,
        "file_size_label": size_label,
        "file_size_bytes": size_bytes,
        "method":          method,
        "classification":  classification,
        "metric":          metric,
        "mean":            round(s["mean"],   6),
        "median":          round(s["median"], 6),
        "min":             round(s["min"],    6),
        "max":             round(s["max"],    6),
        "stdev":           round(s["stdev"],  6),
        "unit":            unit,
        "iterations":      len(values),
    })


_WRITE_CHUNK = 1024 * 1024  # 1 MiB — never loads full file into memory


def _write_plaintext(directory: Path, name: str, size: int) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    p = directory / name
    remaining = size
    with p.open("wb") as f:
        while remaining > 0:
            write_size = min(_WRITE_CHUNK, remaining)
            f.write(os.urandom(write_size))
            remaining -= write_size
    return p


def _timed_encrypt(plaintext: Path, method: str, provider, user) -> tuple[float, int, str]:
    """Run one encrypt iteration; return (elapsed_s, peak_bytes, output_path)."""
    tracemalloc.start()
    t0 = time.perf_counter()
    out = stream_encrypt_file(
        str(plaintext),
        method=method,
        overwrite=True,
        provider=provider,
        user=user,
    )
    t1 = time.perf_counter()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return t1 - t0, peak, out


def _timed_decrypt(enc_path: Path, provider, user) -> tuple[float, int, str]:
    """Run one decrypt iteration; return (elapsed_s, peak_bytes, output_path)."""
    tracemalloc.start()
    t0 = time.perf_counter()
    out = stream_decrypt_file(
        str(enc_path),
        overwrite=True,
        provider=provider,
        user=user,
    )
    t1 = time.perf_counter()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return t1 - t0, peak, out


# ---------------------------------------------------------------------------
# Benchmark 1 — file-size scaling × method (RSA vs ECC)
# ---------------------------------------------------------------------------

@pytest.mark.benchmark
@pytest.mark.parametrize("method", ["rsa", "ecc"])
@pytest.mark.parametrize("size_label,size_bytes", FILE_SIZES)
def test_encrypt_decrypt_by_size(
    size_label: str,
    size_bytes: int,
    method: str,
    bench_workspace: Path,
    bench_users: dict,
    bench_results: list,
) -> None:
    """Measure encrypt/decrypt latency, throughput, memory, and overhead for each
    file size × method combination.  User is admin (high clearance) so
    classification resolves to 'high' in every run.
    """
    user = bench_users["admin"]
    provider = _provider()
    size_mb = size_bytes / (1024 * 1024)

    input_dir = bench_workspace / "input" / "encrypt"
    plaintext = _write_plaintext(input_dir, f"bench_{size_label}_{method}.bin", size_bytes)

    enc_times:   list[float] = []
    enc_mem:     list[int]   = []
    dec_times:   list[float] = []
    dec_mem:     list[int]   = []
    enc_out_path: Path | None = None

    for _ in range(ITERATIONS):
        elapsed, peak, out = _timed_encrypt(plaintext, method, provider, user)
        enc_times.append(elapsed)
        enc_mem.append(peak)
        enc_out_path = Path(out)

    assert enc_out_path is not None
    output_size   = enc_out_path.stat().st_size
    overhead_bytes = output_size - size_bytes

    for _ in range(ITERATIONS):
        elapsed, peak, _ = _timed_decrypt(enc_out_path, provider, user)
        dec_times.append(elapsed)
        dec_mem.append(peak)

    # Constant memory: streaming model must stay well under 10 MB regardless of file size.
    _MEM_LIMIT = 10 * 1024 * 1024
    assert max(enc_mem) < _MEM_LIMIT, (
        f"Encrypt peak memory {max(enc_mem):,} B exceeded {_MEM_LIMIT:,} B for {size_label}"
    )
    assert max(dec_mem) < _MEM_LIMIT, (
        f"Decrypt peak memory {max(dec_mem):,} B exceeded {_MEM_LIMIT:,} B for {size_label}"
    )

    # classification is high (admin user, context={} → policy low → max(3,1)=3 → "high")
    classification = "high"

    _record(bench_results,
            test_name="size_scaling", size_label=size_label, size_bytes=size_bytes,
            method=method, classification=classification,
            metric="encrypt_latency_s", values=enc_times, unit="seconds")

    _record(bench_results,
            test_name="size_scaling", size_label=size_label, size_bytes=size_bytes,
            method=method, classification=classification,
            metric="encrypt_throughput_mbs",
            values=[size_mb / t for t in enc_times], unit="MB/s")

    _record(bench_results,
            test_name="size_scaling", size_label=size_label, size_bytes=size_bytes,
            method=method, classification=classification,
            metric="encrypt_peak_memory_b", values=enc_mem, unit="bytes")

    _record(bench_results,
            test_name="size_scaling", size_label=size_label, size_bytes=size_bytes,
            method=method, classification=classification,
            metric="decrypt_latency_s", values=dec_times, unit="seconds")

    _record(bench_results,
            test_name="size_scaling", size_label=size_label, size_bytes=size_bytes,
            method=method, classification=classification,
            metric="decrypt_throughput_mbs",
            values=[size_mb / t for t in dec_times], unit="MB/s")

    _record(bench_results,
            test_name="size_scaling", size_label=size_label, size_bytes=size_bytes,
            method=method, classification=classification,
            metric="decrypt_peak_memory_b", values=dec_mem, unit="bytes")

    _record(bench_results,
            test_name="size_scaling", size_label=size_label, size_bytes=size_bytes,
            method=method, classification=classification,
            metric="output_overhead_b",
            values=[float(overhead_bytes)] * ITERATIONS, unit="bytes")


# ---------------------------------------------------------------------------
# Benchmark 2 — classification path comparison (low / medium / high)
# ---------------------------------------------------------------------------

@pytest.mark.benchmark
@pytest.mark.parametrize("classification,user_key", CLASSIFICATION_CASES)
@pytest.mark.parametrize("method", ["rsa", "ecc"])
def test_classification_path(
    classification: str,
    user_key: str,
    method: str,
    bench_workspace: Path,
    bench_users: dict,
    bench_results: list,
) -> None:
    """Compare encrypt/decrypt performance across low / medium / high classification
    paths using the matching-clearance user for each level.  Fixed at 1 MB so the
    timing difference reflects authorization + audit overhead rather than I/O.
    """
    size_label  = "1MB"
    size_bytes  = 1 * 1024 * 1024
    size_mb     = size_bytes / (1024 * 1024)
    user        = bench_users[user_key]
    provider    = _provider()

    input_dir = bench_workspace / "input" / "encrypt"
    plaintext = _write_plaintext(
        input_dir, f"bench_cls_{classification}_{method}.bin", size_bytes
    )

    enc_times: list[float] = []
    enc_mem:   list[int]   = []
    dec_times: list[float] = []
    dec_mem:   list[int]   = []
    enc_out_path: Path | None = None

    for _ in range(ITERATIONS):
        elapsed, peak, out = _timed_encrypt(plaintext, method, provider, user)
        enc_times.append(elapsed)
        enc_mem.append(peak)
        enc_out_path = Path(out)

    assert enc_out_path is not None

    for _ in range(ITERATIONS):
        elapsed, peak, _ = _timed_decrypt(enc_out_path, provider, user)
        dec_times.append(elapsed)
        dec_mem.append(peak)

    _record(bench_results,
            test_name="classification_path", size_label=size_label, size_bytes=size_bytes,
            method=method, classification=classification,
            metric="encrypt_latency_s", values=enc_times, unit="seconds")

    _record(bench_results,
            test_name="classification_path", size_label=size_label, size_bytes=size_bytes,
            method=method, classification=classification,
            metric="encrypt_throughput_mbs",
            values=[size_mb / t for t in enc_times], unit="MB/s")

    _record(bench_results,
            test_name="classification_path", size_label=size_label, size_bytes=size_bytes,
            method=method, classification=classification,
            metric="encrypt_peak_memory_b", values=enc_mem, unit="bytes")

    _record(bench_results,
            test_name="classification_path", size_label=size_label, size_bytes=size_bytes,
            method=method, classification=classification,
            metric="decrypt_latency_s", values=dec_times, unit="seconds")

    _record(bench_results,
            test_name="classification_path", size_label=size_label, size_bytes=size_bytes,
            method=method, classification=classification,
            metric="decrypt_throughput_mbs",
            values=[size_mb / t for t in dec_times], unit="MB/s")

    _record(bench_results,
            test_name="classification_path", size_label=size_label, size_bytes=size_bytes,
            method=method, classification=classification,
            metric="decrypt_peak_memory_b", values=dec_mem, unit="bytes")
