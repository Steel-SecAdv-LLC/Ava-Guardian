#!/usr/bin/env python3
# Copyright 2025 Steel Security Advisors LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Ava Guardian Security Monitor
==============================

3R Mechanism: Resonance-Recursion-Refactoring for runtime security analysis.

The 3R Mechanism is a novel security monitoring framework developed for
Ava Guardian by Steel Security Advisors LLC. It provides three complementary
approaches to runtime security analysis without compromising cryptographic
integrity or performance.

Copyright (C) 2025 Steel Security Advisors LLC
Author: Andrew E. A.
License: Apache 2.0
"""

import ast
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
from scipy.fft import fft, fftfreq

__version__ = "1.0.0"
__all__ = [
    "TimingAnomaly",
    "PatternAnomaly",
    "ResonanceTimingMonitor",
    "RecursionPatternMonitor",
    "RefactoringAnalyzer",
    "AvaGuardianMonitor",
]


@dataclass
class TimingAnomaly:
    """
    Detected timing side-channel anomaly.

    Attributes:
        operation: Name of the cryptographic operation
        expected_ms: Baseline expected duration in milliseconds
        observed_ms: Actual observed duration in milliseconds
        deviation_sigma: Number of standard deviations from baseline
        severity: Alert level ('info', 'warning', 'critical')
        timestamp: Unix timestamp of detection
    """

    operation: str
    expected_ms: float
    observed_ms: float
    deviation_sigma: float
    severity: str  # 'info', 'warning', 'critical'
    timestamp: float


@dataclass
class PatternAnomaly:
    """
    Detected signing pattern anomaly.

    Attributes:
        pattern_type: Type of pattern anomaly detected
        confidence: Confidence score (0.0 to 1.0)
        details: Additional context-specific details
        severity: Alert level ('info', 'warning', 'critical')
    """

    pattern_type: str
    confidence: float
    details: Dict
    severity: str


class ResonanceTimingMonitor:
    """
    Detect timing attacks via frequency-domain analysis.

    Uses FFT-based resonance detection to identify periodic timing patterns
    that may indicate side-channel vulnerabilities in cryptographic
    operations.

    Timing side-channels can leak information through:
    - Cache timing attacks
    - Branch prediction patterns
    - Memory access patterns
    - CPU microarchitecture behavior

    The resonance approach detects these by identifying periodic patterns
    in operation timings that deviate from expected random noise.
    """

    def __init__(
        self,
        threshold_sigma: float = 3.0,
        window_size: int = 100,
        max_history: int = 10000,
    ) -> None:
        """
        Initialize timing monitor.

        Args:
            threshold_sigma: Standard deviations for anomaly detection.
                Values > 3.0 indicate statistical significance.
            window_size: Number of samples for frequency analysis.
                Larger windows provide better frequency resolution.
            max_history: Maximum history entries per operation.
                Limits memory usage for long-running systems.
        """
        self.threshold = threshold_sigma
        self.window_size = window_size
        self.max_history = max_history
        self.timing_history: Dict[str, List[float]] = {}
        self.baseline_stats: Dict[str, Dict[str, float]] = {}

    def record_timing(
        self, operation: str, duration_ms: float
    ) -> Optional[TimingAnomaly]:
        """
        Record operation timing and detect anomalies.

        Args:
            operation: Name of cryptographic operation (e.g., 'ed25519_sign')
            duration_ms: Observed duration in milliseconds

        Returns:
            TimingAnomaly if statistical anomaly detected, None otherwise

        Note:
            Requires 30+ samples before anomaly detection activates.
            This establishes a stable baseline distribution.
        """
        if operation not in self.timing_history:
            self.timing_history[operation] = []

        self.timing_history[operation].append(duration_ms)
        self._prune_history(operation)

        # Need baseline before detection
        if len(self.timing_history[operation]) < 30:
            return None

        # Update baseline statistics
        timings = np.array(
            self.timing_history[operation][-self.window_size :]
        )
        mean = np.mean(timings)
        std = np.std(timings)

        self.baseline_stats[operation] = {"mean": mean, "std": std}

        # Detect statistical anomaly
        if std > 0:
            deviation = abs(duration_ms - mean) / std

            if deviation > self.threshold:
                severity = "critical" if deviation > 5.0 else "warning"
                return TimingAnomaly(
                    operation=operation,
                    expected_ms=mean,
                    observed_ms=duration_ms,
                    deviation_sigma=deviation,
                    severity=severity,
                    timestamp=time.time(),
                )

        return None

    def detect_resonance(self, operation: str) -> Dict:
        """
        Apply FFT to detect periodic timing patterns (resonance).

        Periodic patterns may indicate:
        - Cache timing attacks (consistent memory access patterns)
        - Branch prediction leakage (repeated conditional paths)
        - Memory access patterns (array indexing correlations)

        Returns:
            Dict with:
                - dominant_frequency: Primary periodic component
                - dominant_power: Power of dominant frequency
                - mean_power: Average power across spectrum
                - resonance_ratio: Ratio of dominant to mean power
                - has_resonance: Boolean flag (ratio > 3.0)

        Note:
            Requires minimum 8 samples. Returns empty dict if insufficient
            data.
        """
        if operation not in self.timing_history:
            return {}

        timings = np.array(
            self.timing_history[operation][-self.window_size :]
        )

        if len(timings) < 8:
            return {}

        # FFT analysis
        fft_result = fft(timings)
        freqs = fftfreq(len(timings))
        power = np.abs(fft_result) ** 2

        # Find dominant frequency (excluding DC component)
        dominant_idx = np.argmax(power[1:]) + 1
        dominant_freq = freqs[dominant_idx]
        dominant_power = power[dominant_idx]

        # Calculate mean power for comparison
        mean_power = np.mean(power[1:])

        return {
            "dominant_frequency": float(dominant_freq),
            "dominant_power": float(dominant_power),
            "mean_power": float(mean_power),
            "resonance_ratio": (
                float(dominant_power / mean_power) if mean_power > 0 else 0
            ),
            "has_resonance": dominant_power > 3.0 * mean_power,
        }

    def _prune_history(self, operation: str) -> None:
        """Limit memory usage by pruning old timing data."""
        if len(self.timing_history[operation]) > self.max_history:
            self.timing_history[operation] = self.timing_history[operation][
                -self.max_history :
            ]


class RecursionPatternMonitor:
    """
    Hierarchical analysis of signing patterns.

    Detects anomalies in key usage, signing frequency, and package
    characteristics using recursive feature extraction across multiple
    time scales. This multi-resolution approach can identify both
    short-term spikes and long-term drift in signing behavior.
    """

    def __init__(
        self, max_depth: int = 3, max_history: int = 10000
    ) -> None:
        """
        Initialize pattern monitor.

        Args:
            max_depth: Maximum recursion depth for hierarchical analysis.
                Depth 0 = raw data, Depth 1 = 2x downsampled, etc.
            max_history: Maximum package history entries to retain.
        """
        self.max_depth = max_depth
        self.max_history = max_history
        self.package_history: List[Dict] = []

    def record_package(self, package_metadata: Dict) -> None:
        """
        Record package signing event.

        Args:
            package_metadata: Dict containing:
                - author: Package author identifier
                - code_count: Number of DNA codes in package
                - content_hash: First 16 chars of content hash
                - (optional) Additional application-specific fields
        """
        self.package_history.append({"timestamp": time.time(), **package_metadata})

        # Prune old history
        if len(self.package_history) > self.max_history:
            self.package_history = self.package_history[-self.max_history :]

    def analyze_patterns(self) -> Dict:
        """
        Perform hierarchical pattern analysis.

        Returns:
            Dict with:
                - status: 'insufficient_data' or 'analyzed'
                - features: Hierarchical feature dictionary (if analyzed)
                - anomalies: List of detected anomalies (if analyzed)

        Note:
            Requires minimum 10 packages for analysis.
        """
        if len(self.package_history) < 10:
            return {"status": "insufficient_data"}

        # Extract time series features
        timestamps = [p["timestamp"] for p in self.package_history]
        intervals = np.diff(timestamps)

        # Recursive hierarchical analysis
        features = self._recursive_extract(intervals, depth=0)

        # Detect anomalies
        anomalies = []

        # Check for unusual signing frequency
        if "level_0_mean" in features and "level_0_std" in features:
            recent_interval = intervals[-1] if len(intervals) > 0 else 0
            if features["level_0_std"] > 0:
                z_score = (
                    abs(recent_interval - features["level_0_mean"])
                    / features["level_0_std"]
                )

                if z_score > 3.0:
                    anomalies.append(
                        {
                            "type": "unusual_frequency",
                            "z_score": float(z_score),
                            "severity": "warning" if z_score < 5.0 else "critical",
                            "details": {
                                "expected_interval_sec": features["level_0_mean"],
                                "observed_interval_sec": recent_interval,
                            },
                        }
                    )

        # Check for package size anomalies
        code_counts = [p.get("code_count", 0) for p in self.package_history]
        if len(code_counts) > 10:
            mean_count = np.mean(code_counts)
            std_count = np.std(code_counts)
            recent_count = code_counts[-1]

            if std_count > 0:
                z_score = abs(recent_count - mean_count) / std_count
                if z_score > 3.0:
                    anomalies.append(
                        {
                            "type": "unusual_package_size",
                            "z_score": float(z_score),
                            "severity": "info",
                            "details": {
                                "expected_codes": mean_count,
                                "observed_codes": recent_count,
                            },
                        }
                    )

        return {
            "status": "analyzed",
            "features": features,
            "anomalies": anomalies,
            "total_packages": len(self.package_history),
        }

    def _recursive_extract(self, data: np.ndarray, depth: int) -> Dict:
        """
        Recursively extract features at multiple scales.

        Implements multi-resolution analysis by:
        1. Computing statistics at current scale
        2. Downsampling data (take every 2nd element)
        3. Recursing until max_depth or insufficient data

        Args:
            data: Time series data (e.g., inter-package intervals)
            depth: Current recursion depth

        Returns:
            Dict of features with keys like:
                'level_0_mean', 'level_0_std', 'level_1_mean', ...
        """
        if depth >= self.max_depth or len(data) < 2:
            return {}

        features = {
            f"level_{depth}_mean": float(np.mean(data)),
            f"level_{depth}_std": float(np.std(data)),
            f"level_{depth}_range": float(np.max(data) - np.min(data)),
            f"level_{depth}_samples": len(data),
        }

        # Downsample for next level (every 2nd element)
        if len(data) >= 4:
            downsampled = data[::2]
            deeper_features = self._recursive_extract(downsampled, depth + 1)
            features.update(deeper_features)

        return features


class RefactoringAnalyzer:
    """
    Read-only code complexity analysis.

    **CRITICAL SECURITY CONSTRAINT**: This analyzer operates in read-only
    mode and NEVER modifies cryptographic code automatically. It provides
    metrics for manual human review only.

    Automatic code modification of security-critical code is dangerous
    because:
    - May introduce subtle vulnerabilities
    - Bypasses code review processes
    - Could weaken cryptographic guarantees
    - Violates principle of least privilege

    This analyzer calculates cyclomatic complexity and provides
    recommendations, but all refactoring decisions must be made by
    qualified security engineers.
    """

    def __init__(self) -> None:
        """Initialize analyzer with empty cache."""
        self.analysis_cache: Dict[str, Dict] = {}

    def analyze_file(self, filepath: Path) -> Dict:
        """
        Analyze Python file complexity (read-only).

        Calculates:
        - Total functions and classes
        - Per-function cyclomatic complexity
        - Lines of code
        - Complexity distribution

        Args:
            filepath: Path to Python file to analyze

        Returns:
            Dict with:
                - total_functions: Count of function definitions
                - total_classes: Count of class definitions
                - total_lines: Total lines in file
                - functions: List of per-function metrics
                - complexity_summary: Aggregate statistics
                - (error: str if parsing fails)

        Note:
            Uses Python's ast module for parsing. Only analyzes
            syntactically valid Python files.
        """
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                source = f.read()

            tree = ast.parse(source)

            metrics = {
                "total_functions": 0,
                "total_classes": 0,
                "total_lines": len(source.splitlines()),
                "functions": [],
            }

            complexity_values = []

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    metrics["total_functions"] += 1
                    complexity = self._calculate_complexity(node)
                    complexity_values.append(complexity)

                    function_info = {
                        "name": node.name,
                        "complexity": complexity,
                        "lines": (
                            node.end_lineno - node.lineno
                            if hasattr(node, "end_lineno")
                            else 0
                        ),
                        "recommendation": self._get_recommendation(complexity),
                    }
                    metrics["functions"].append(function_info)

                elif isinstance(node, ast.ClassDef):
                    metrics["total_classes"] += 1

            # Add complexity summary
            if complexity_values:
                metrics["complexity_summary"] = {
                    "mean": float(np.mean(complexity_values)),
                    "max": int(np.max(complexity_values)),
                    "high_complexity_functions": sum(
                        1 for c in complexity_values if c > 10
                    ),
                }

            return metrics

        except Exception as e:
            return {"error": str(e), "filepath": str(filepath)}

    def _calculate_complexity(self, node: ast.FunctionDef) -> int:
        """
        Calculate cyclomatic complexity using standard formula.

        Cyclomatic complexity M = E - N + 2P, simplified to:
        M = 1 + (number of decision points)

        Decision points:
        - if, elif, else
        - for, while loops
        - except handlers
        - boolean operators (and, or)
        - ternary operators

        Args:
            node: AST FunctionDef node

        Returns:
            Integer complexity score. Guidelines:
                1-10: Simple, easy to test
                11-20: Moderate, may need refactoring
                21+: Complex, should refactor
        """
        complexity = 1  # Base complexity

        for child in ast.walk(node):
            # Conditional branches
            if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                complexity += 1

            # Boolean operators add decision points
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1

            # Ternary expressions
            elif isinstance(child, ast.IfExp):
                complexity += 1

        return complexity

    def _get_recommendation(self, complexity: int) -> str:
        """
        Provide refactoring recommendation based on complexity.

        Args:
            complexity: Cyclomatic complexity score

        Returns:
            Human-readable recommendation string
        """
        if complexity <= 10:
            return "Acceptable complexity"
        elif complexity <= 20:
            return "Consider refactoring - moderate complexity"
        else:
            return "Refactor recommended - high complexity"


class AvaGuardianMonitor:
    """
    Unified monitoring interface for Ava Guardian.

    Combines 3R Mechanism components (Resonance-Recursion-Refactoring)
    for comprehensive security monitoring without compromising cryptographic
    integrity or performance.

    Design Principles:
    - Opt-in: Disabled by default for zero overhead
    - Non-invasive: Read-only analysis, never modifies crypto code
    - Lightweight: <2% performance overhead when enabled
    - Observable: Comprehensive reporting for security teams

    Usage:
        >>> monitor = AvaGuardianMonitor(enabled=True)
        >>> pkg = create_crypto_package(codes, params, kms, monitor=monitor)
        >>> report = monitor.get_security_report()
        >>> print(f"Alerts: {report['total_alerts']}")
    """

    def __init__(self, enabled: bool = False, alert_retention: int = 1000) -> None:
        """
        Initialize monitor.

        Args:
            enabled: Whether monitoring is active. Default False for
                zero-overhead operation when not needed.
            alert_retention: Maximum alerts to retain in memory.
                Prevents unbounded memory growth.
        """
        self.enabled = enabled
        self.alert_retention = alert_retention
        self.timing = ResonanceTimingMonitor()
        self.patterns = RecursionPatternMonitor()
        self.analyzer = RefactoringAnalyzer()
        self.alerts: List[Dict] = []

    def monitor_crypto_operation(self, operation: str, duration_ms: float) -> None:
        """
        Monitor cryptographic operation timing.

        Records operation duration and checks for timing anomalies
        that could indicate side-channel vulnerabilities.

        Args:
            operation: Operation name (e.g., 'ed25519_sign',
                'dilithium_verify')
            duration_ms: Operation duration in milliseconds
        """
        if not self.enabled:
            return

        anomaly = self.timing.record_timing(operation, duration_ms)
        if anomaly:
            self.alerts.append(
                {"type": "timing", "anomaly": anomaly, "timestamp": time.time()}
            )
            self._prune_alerts()

    def record_package_signing(self, metadata: Dict) -> None:
        """
        Record package signing event for pattern analysis.

        Args:
            metadata: Package metadata dict containing:
                - author: Package signer
                - code_count: Number of DNA codes
                - content_hash: Truncated content hash
        """
        if not self.enabled:
            return

        self.patterns.record_package(metadata)

        # Check for pattern anomalies
        analysis = self.patterns.analyze_patterns()
        if analysis.get("status") == "analyzed":
            for anomaly in analysis.get("anomalies", []):
                self.alerts.append(
                    {"type": "pattern", "anomaly": anomaly, "timestamp": time.time()}
                )
                self._prune_alerts()

    def analyze_codebase(self, directory: Path) -> Dict:
        """
        Analyze codebase complexity (read-only).

        Scans all Python files in directory and calculates
        complexity metrics. Does NOT modify any files.

        Args:
            directory: Root directory to analyze

        Returns:
            Dict with:
                - files_analyzed: List of file analyses
                - aggregate_metrics: Overall complexity statistics

        Warning:
            This is a read-only analysis tool. All refactoring
            decisions must be made by qualified engineers through
            proper code review processes.
        """
        if not self.enabled:
            return {"status": "monitoring_disabled"}

        results = []
        for py_file in directory.rglob("*.py"):
            analysis = self.analyzer.analyze_file(py_file)
            results.append({"filepath": str(py_file), "analysis": analysis})

        # Aggregate statistics
        all_complexities = []
        for r in results:
            if "functions" in r["analysis"]:
                all_complexities.extend(
                    [f["complexity"] for f in r["analysis"]["functions"]]
                )

        aggregate = {}
        if all_complexities:
            aggregate = {
                "total_functions": len(all_complexities),
                "mean_complexity": float(np.mean(all_complexities)),
                "max_complexity": int(np.max(all_complexities)),
                "high_complexity_count": sum(1 for c in all_complexities if c > 10),
            }

        return {
            "status": "analyzed",
            "files_analyzed": results,
            "aggregate_metrics": aggregate,
        }

    def get_security_report(self) -> Dict:
        """
        Generate comprehensive security report.

        Returns:
            Dict containing:
                - status: 'monitoring_disabled' or 'active'
                - timing_baseline: Per-operation baseline statistics
                - resonance_analysis: Frequency-domain analysis results
                - pattern_analysis: Hierarchical pattern analysis
                - recent_alerts: Last 10 alerts
                - total_alerts: Total alert count
                - recommendations: Security recommendations (if any)
        """
        if not self.enabled:
            return {"status": "monitoring_disabled"}

        report = {
            "status": "active",
            "timing_baseline": self.timing.baseline_stats,
            "pattern_analysis": self.patterns.analyze_patterns(),
            "recent_alerts": self.alerts[-10:],
            "total_alerts": len(self.alerts),
            "recommendations": [],
        }

        # Add resonance analysis for monitored operations
        resonance_data = {}
        for operation in self.timing.timing_history.keys():
            resonance = self.timing.detect_resonance(operation)
            if resonance.get("has_resonance"):
                resonance_data[operation] = resonance

        if resonance_data:
            report["resonance_analysis"] = resonance_data
            report["recommendations"].append(
                "Resonance detected in timing patterns. "
                "Review for potential side-channel vulnerabilities."
            )

        # Add pattern-based recommendations
        if report["pattern_analysis"].get("status") == "analyzed":
            anomalies = report["pattern_analysis"].get("anomalies", [])
            if any(a["severity"] == "critical" for a in anomalies):
                report["recommendations"].append(
                    "Critical pattern anomalies detected. "
                    "Immediate security review recommended."
                )

        return report

    def _prune_alerts(self) -> None:
        """Limit memory usage by pruning old alerts."""
        if len(self.alerts) > self.alert_retention:
            self.alerts = self.alerts[-self.alert_retention :]


# Module-level convenience functions


def create_monitor(
    enabled: bool = False, alert_retention: int = 1000
) -> AvaGuardianMonitor:
    """
    Factory function for creating monitor instances.

    Args:
        enabled: Whether monitoring is active
        alert_retention: Maximum alerts to retain

    Returns:
        Configured AvaGuardianMonitor instance
    """
    return AvaGuardianMonitor(enabled=enabled, alert_retention=alert_retention)
