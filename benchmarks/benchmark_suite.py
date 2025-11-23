#!/usr/bin/env python3
"""
Ava Guardian ♱ Comprehensive Benchmark Suite

Measures performance of all cryptographic layers and compares against
industry-leading implementations and published benchmarks.

Copyright (C) 2025 Steel Security Advisors LLC
"""

import hashlib
import hmac
import json
import secrets
import statistics
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Add parent directory to path to import dna_guardian_secure
sys.path.insert(0, str(Path(__file__).parent.parent))

from dna_guardian_secure import (
    DILITHIUM_AVAILABLE,
    DILITHIUM_BACKEND,
    MASTER_DNA_CODES,
    MASTER_HELIX_PARAMS,
    canonical_hash_dna,
    create_crypto_package,
    dilithium_sign,
    dilithium_verify,
    ed25519_sign,
    ed25519_verify,
    generate_dilithium_keypair,
    generate_ed25519_keypair,
    generate_key_management_system,
    hmac_authenticate,
    hmac_verify,
    verify_crypto_package,
)


@dataclass
class BenchmarkResult:
    """Single benchmark measurement."""

    operation: str
    mean_time_us: float  # microseconds
    std_dev_us: float
    ops_per_second: float
    iterations: int
    size_bytes: Optional[int] = None  # For signatures, keys, etc.


@dataclass
class ComparisonData:
    """External benchmark data for comparison."""

    source: str
    operation: str
    time_us: Optional[float] = None
    ops_per_second: Optional[float] = None
    platform: Optional[str] = None
    notes: Optional[str] = None


class BenchmarkSuite:
    """Comprehensive cryptographic benchmark suite."""

    def __init__(self, iterations: int = 1000):
        self.iterations = iterations
        self.results: List[BenchmarkResult] = []
        self.comparisons: List[ComparisonData] = []

        # Initialize test data
        self.test_message = b"Test message for cryptographic benchmarking"
        self.kms = generate_key_management_system("benchmark")

        # Generate Dilithium keys if available
        if DILITHIUM_AVAILABLE:
            self.dilithium_keypair = generate_dilithium_keypair()
        else:
            self.dilithium_keypair = None

    def benchmark_operation(
        self, operation_name: str, operation_func, iterations: int = None
    ) -> BenchmarkResult:
        """
        Benchmark a single operation.

        Args:
            operation_name: Name of the operation
            operation_func: Function to benchmark (should take no arguments)
            iterations: Number of iterations (default: self.iterations)

        Returns:
            BenchmarkResult with timing statistics
        """
        if iterations is None:
            iterations = self.iterations

        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            operation_func()
            end = time.perf_counter()
            times.append((end - start) * 1_000_000)  # Convert to microseconds

        mean_time = statistics.mean(times)
        std_dev = statistics.stdev(times) if len(times) > 1 else 0.0
        ops_per_sec = 1_000_000 / mean_time  # microseconds to ops/sec

        result = BenchmarkResult(
            operation=operation_name,
            mean_time_us=mean_time,
            std_dev_us=std_dev,
            ops_per_second=ops_per_sec,
            iterations=iterations,
        )

        self.results.append(result)
        return result

    def benchmark_sha3_256(self):
        """Benchmark SHA3-256 hashing."""
        print("Benchmarking SHA3-256...")

        # Benchmark canonical hash with DNA codes
        result = self.benchmark_operation(
            "SHA3-256 (DNA codes + helix params)",
            lambda: canonical_hash_dna(MASTER_DNA_CODES, MASTER_HELIX_PARAMS),
        )
        print(
            f"  ✓ {result.operation}: {result.mean_time_us:.2f}±{result.std_dev_us:.2f} μs ({result.ops_per_second:,.0f} ops/sec)"
        )

        # Benchmark raw SHA3-256
        result = self.benchmark_operation(
            "SHA3-256 (raw, 43 bytes)", lambda: hashlib.sha3_256(self.test_message).digest()
        )
        print(
            f"  ✓ {result.operation}: {result.mean_time_us:.2f}±{result.std_dev_us:.2f} μs ({result.ops_per_second:,.0f} ops/sec)"
        )

    def benchmark_hmac(self):
        """Benchmark HMAC-SHA3-256."""
        print("\nBenchmarking HMAC-SHA3-256...")

        hmac_key = self.kms.hmac_key
        test_hash = hashlib.sha3_256(self.test_message).digest()

        # Benchmark HMAC authentication
        result = self.benchmark_operation(
            "HMAC-SHA3-256 (authenticate)", lambda: hmac_authenticate(test_hash, hmac_key)
        )
        print(
            f"  ✓ {result.operation}: {result.mean_time_us:.2f}±{result.std_dev_us:.2f} μs ({result.ops_per_second:,.0f} ops/sec)"
        )

        # Benchmark HMAC verification
        hmac_tag = hmac_authenticate(test_hash, hmac_key)
        result = self.benchmark_operation(
            "HMAC-SHA3-256 (verify)", lambda: hmac_verify(test_hash, hmac_tag, hmac_key)
        )
        print(
            f"  ✓ {result.operation}: {result.mean_time_us:.2f}±{result.std_dev_us:.2f} μs ({result.ops_per_second:,.0f} ops/sec)"
        )

    def benchmark_ed25519(self):
        """Benchmark Ed25519 signatures."""
        print("\nBenchmarking Ed25519...")

        private_key = self.kms.ed25519_keypair.private_key
        public_key = self.kms.ed25519_keypair.public_key
        test_hash = hashlib.sha3_256(self.test_message).digest()

        # Benchmark key generation
        result = self.benchmark_operation(
            "Ed25519 (keygen)", lambda: generate_ed25519_keypair(), iterations=100
        )
        print(
            f"  ✓ {result.operation}: {result.mean_time_us:.2f}±{result.std_dev_us:.2f} μs ({result.ops_per_second:,.0f} ops/sec)"
        )

        # Benchmark signing
        result = self.benchmark_operation(
            "Ed25519 (sign)", lambda: ed25519_sign(test_hash, private_key)
        )
        result.size_bytes = 64  # Ed25519 signature size
        print(
            f"  ✓ {result.operation}: {result.mean_time_us:.2f}±{result.std_dev_us:.2f} μs ({result.ops_per_second:,.0f} ops/sec, {result.size_bytes} bytes)"
        )

        # Benchmark verification
        signature = ed25519_sign(test_hash, private_key)
        result = self.benchmark_operation(
            "Ed25519 (verify)", lambda: ed25519_verify(test_hash, signature, public_key)
        )
        print(
            f"  ✓ {result.operation}: {result.mean_time_us:.2f}±{result.std_dev_us:.2f} μs ({result.ops_per_second:,.0f} ops/sec)"
        )

    def benchmark_dilithium(self):
        """Benchmark CRYSTALS-Dilithium signatures."""
        if not DILITHIUM_AVAILABLE:
            print("\n⚠ Dilithium not available - skipping benchmark")
            return

        print(f"\nBenchmarking CRYSTALS-Dilithium3 ({DILITHIUM_BACKEND} backend)...")

        private_key = self.dilithium_keypair.private_key
        public_key = self.dilithium_keypair.public_key
        test_hash = hashlib.sha3_256(self.test_message).digest()

        # Benchmark key generation
        result = self.benchmark_operation(
            "Dilithium3 (keygen)", lambda: generate_dilithium_keypair(), iterations=50
        )
        result.size_bytes = len(public_key)
        print(
            f"  ✓ {result.operation}: {result.mean_time_us:.2f}±{result.std_dev_us:.2f} μs ({result.ops_per_second:,.0f} ops/sec, pk={result.size_bytes} bytes)"
        )

        # Benchmark signing
        result = self.benchmark_operation(
            "Dilithium3 (sign)", lambda: dilithium_sign(test_hash, private_key), iterations=50
        )
        signature = dilithium_sign(test_hash, private_key)
        result.size_bytes = len(signature)
        print(
            f"  ✓ {result.operation}: {result.mean_time_us:.2f}±{result.std_dev_us:.2f} μs ({result.ops_per_second:,.0f} ops/sec, {result.size_bytes} bytes)"
        )

        # Benchmark verification
        result = self.benchmark_operation(
            "Dilithium3 (verify)",
            lambda: dilithium_verify(test_hash, signature, public_key),
            iterations=100,
        )
        print(
            f"  ✓ {result.operation}: {result.mean_time_us:.2f}±{result.std_dev_us:.2f} μs ({result.ops_per_second:,.0f} ops/sec)"
        )

    def benchmark_complete_system(self):
        """Benchmark complete 6-layer system."""
        print("\nBenchmarking Complete AG♱ System...")

        # Benchmark package creation
        result = self.benchmark_operation(
            "AG♱ Package Creation (6 layers)",
            lambda: create_crypto_package(
                MASTER_DNA_CODES, MASTER_HELIX_PARAMS, self.kms, "benchmark"
            ),
            iterations=100,
        )
        print(
            f"  ✓ {result.operation}: {result.mean_time_us:.2f}±{result.std_dev_us:.2f} μs ({result.ops_per_second:,.0f} ops/sec)"
        )

        # Benchmark package verification
        package = create_crypto_package(
            MASTER_DNA_CODES, MASTER_HELIX_PARAMS, self.kms, "benchmark"
        )
        result = self.benchmark_operation(
            "AG♱ Package Verification (6 layers)",
            lambda: verify_crypto_package(
                MASTER_DNA_CODES, MASTER_HELIX_PARAMS, package, self.kms.hmac_key
            ),
            iterations=100,
        )
        print(
            f"  ✓ {result.operation}: {result.mean_time_us:.2f}±{result.std_dev_us:.2f} μs ({result.ops_per_second:,.0f} ops/sec)"
        )

        # Calculate total package size
        package_size = (
            32  # SHA3-256 hash
            + 32  # HMAC tag
            + 64  # Ed25519 signature
            + (len(signature) if DILITHIUM_AVAILABLE else 3293)  # Dilithium signature
            + 32  # Ed25519 public key
            + (len(public_key) if DILITHIUM_AVAILABLE else 1952)  # Dilithium public key
        )
        print(f"  ℹ Total package size: ~{package_size} bytes")

    def add_external_benchmarks(self):
        """Add external benchmark data for comparison."""
        print("\nAdding external benchmark comparisons...")

        # SUPERCOP data (typical x86_64 performance)
        # Source: bench.cr.yp.to
        self.comparisons.extend(
            [
                ComparisonData(
                    source="SUPERCOP",
                    operation="Ed25519 (sign)",
                    time_us=60.0,
                    platform="Intel Core i7",
                    notes="Typical fast implementation",
                ),
                ComparisonData(
                    source="SUPERCOP",
                    operation="Ed25519 (verify)",
                    time_us=160.0,
                    platform="Intel Core i7",
                    notes="Typical fast implementation",
                ),
                ComparisonData(
                    source="SUPERCOP",
                    operation="SHA3-256",
                    ops_per_second=1_000_000,
                    platform="Intel Core i7",
                    notes="~1 μs per hash",
                ),
            ]
        )

        # Open Quantum Safe liboqs benchmarks
        # Source: openquantumsafe.org benchmarks
        self.comparisons.extend(
            [
                ComparisonData(
                    source="Open Quantum Safe",
                    operation="Dilithium3 (keygen)",
                    time_us=200.0,
                    platform="x86_64",
                    notes="NIST Level 3",
                ),
                ComparisonData(
                    source="Open Quantum Safe",
                    operation="Dilithium3 (sign)",
                    time_us=800.0,
                    platform="x86_64",
                    notes="NIST Level 3",
                ),
                ComparisonData(
                    source="Open Quantum Safe",
                    operation="Dilithium3 (verify)",
                    time_us=150.0,
                    platform="x86_64",
                    notes="NIST Level 3",
                ),
            ]
        )

        # libsodium benchmarks (Ed25519 reference)
        self.comparisons.extend(
            [
                ComparisonData(
                    source="libsodium",
                    operation="Ed25519 (sign)",
                    ops_per_second=16_000,
                    platform="Various",
                    notes="NaCl crypto library",
                ),
                ComparisonData(
                    source="libsodium",
                    operation="Ed25519 (verify)",
                    ops_per_second=62_000,
                    platform="Various",
                    notes="NaCl crypto library",
                ),
            ]
        )

        print(f"  ✓ Added {len(self.comparisons)} external benchmarks")

    def generate_report(self) -> str:
        """Generate comprehensive benchmark report."""
        report = []
        report.append("=" * 80)
        report.append("Ava Guardian ♱ (AG♱) - Cryptographic Performance Benchmark")
        report.append("=" * 80)
        report.append(f"\nConfiguration:")
        report.append(f"  Iterations: {self.iterations}")
        report.append(f"  Dilithium Backend: {DILITHIUM_BACKEND or 'Not Available'}")
        report.append(f"\n{'Operation':<45} {'Time (μs)':<15} {'Ops/Sec':<15} {'Size'}")
        report.append("-" * 80)

        for result in self.results:
            size_str = f"{result.size_bytes} B" if result.size_bytes else "-"
            report.append(
                f"{result.operation:<45} "
                f"{result.mean_time_us:>8.2f}±{result.std_dev_us:<4.2f} "
                f"{result.ops_per_second:>13,.0f} "
                f"{size_str:>10}"
            )

        if self.comparisons:
            report.append("\n" + "=" * 80)
            report.append("External Benchmark Comparisons")
            report.append("=" * 80)
            report.append(f"\n{'Source':<20} {'Operation':<25} {'Time (μs)':<15} {'Notes'}")
            report.append("-" * 80)

            for comp in self.comparisons:
                time_str = (
                    f"{comp.time_us:.2f}" if comp.time_us else f"~{1_000_000/comp.ops_per_second:.2f}" if comp.ops_per_second else "N/A"
                )
                report.append(
                    f"{comp.source:<20} {comp.operation:<25} {time_str:<15} {comp.notes or ''}"
                )

        report.append("\n" + "=" * 80)
        return "\n".join(report)

    def save_results(self, output_dir: Path):
        """Save benchmark results to JSON files."""
        output_dir.mkdir(exist_ok=True, parents=True)

        # Save detailed results
        results_file = output_dir / "benchmark_results.json"
        with open(results_file, "w") as f:
            json.dump(
                {
                    "results": [asdict(r) for r in self.results],
                    "comparisons": [asdict(c) for c in self.comparisons],
                    "config": {
                        "iterations": self.iterations,
                        "dilithium_backend": DILITHIUM_BACKEND,
                        "dilithium_available": DILITHIUM_AVAILABLE,
                    },
                },
                f,
                indent=2,
            )
        print(f"\n✓ Results saved to {results_file}")

        # Save report
        report_file = output_dir / "benchmark_report.txt"
        with open(report_file, "w") as f:
            f.write(self.generate_report())
        print(f"✓ Report saved to {report_file}")


def main():
    """Run comprehensive benchmark suite."""
    print("Starting Ava Guardian ♱ Comprehensive Benchmark Suite\n")

    suite = BenchmarkSuite(iterations=1000)

    # Run all benchmarks
    suite.benchmark_sha3_256()
    suite.benchmark_hmac()
    suite.benchmark_ed25519()
    suite.benchmark_dilithium()
    suite.benchmark_complete_system()

    # Add external comparisons
    suite.add_external_benchmarks()

    # Generate and display report
    print("\n" + suite.generate_report())

    # Save results
    output_dir = Path(__file__).parent / "results"
    suite.save_results(output_dir)

    print("\n✓ Benchmark suite completed successfully")


if __name__ == "__main__":
    main()
