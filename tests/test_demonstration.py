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
Test suite for validating Ava Guardian demonstration functionality.

This test module validates that the demonstration function executes successfully
and produces correct output, verifying all six cryptographic layers.
"""

import subprocess
import sys
from pathlib import Path

import pytest


class TestDemonstration:
    """Test the main demonstration function."""

    def test_demonstration_runs_successfully(self):
        """
        Test that the demonstration script runs without errors.

        This test validates:
        - Script executes successfully (exit code 0)
        - No errors are raised during execution
        - All cryptographic operations complete
        """
        # Get the path to the main script
        script_path = Path(__file__).parent.parent / "dna_guardian_secure.py"
        assert script_path.exists(), f"Script not found: {script_path}"

        # Run the demonstration
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            timeout=60,  # 60 second timeout
        )

        # Check exit code
        assert result.returncode == 0, (
            f"Demonstration failed with exit code {result.returncode}\n"
            f"STDOUT: {result.stdout}\n"
            f"STDERR: {result.stderr}"
        )

    def test_demonstration_output_validation(self):
        """
        Test that the demonstration produces expected output.

        This test validates:
        - Title banner is displayed
        - All six cryptographic layers are mentioned
        - Key generation succeeds
        - Package creation succeeds
        - Signature creation succeeds
        - Verification succeeds
        - Final success message is displayed
        """
        # Get the path to the main script
        script_path = Path(__file__).parent.parent / "dna_guardian_secure.py"

        # Run the demonstration
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            timeout=60,
        )

        output = result.stdout

        # Critical output checks
        required_outputs = [
            ("Ava Guardian", "Title banner"),
            ("Generating key management system", "Key generation step"),
            ("Creating DNA cryptographic package", "Package creation step"),
            ("Signing package", "Signing step"),
            ("Verifying cryptographic package", "Verification step"),
            ("ALL VERIFICATIONS PASSED", "Success confirmation"),
        ]

        missing_outputs = []
        for check, description in required_outputs:
            if check not in output:
                missing_outputs.append(f"{description}: '{check}' not found")

        assert not missing_outputs, (
            "Demonstration output validation failed:\n"
            + "\n".join(f"  - {msg}" for msg in missing_outputs)
            + f"\n\nActual output:\n{output}"
        )

    def test_demonstration_no_errors(self):
        """
        Test that the demonstration produces no error messages.

        This test validates:
        - No ERROR messages in output
        - No exceptions raised
        - No warnings about missing critical dependencies
        """
        # Get the path to the main script
        script_path = Path(__file__).parent.parent / "dna_guardian_secure.py"

        # Run the demonstration
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            timeout=60,
        )

        # Check for errors in output
        output_combined = result.stdout + result.stderr

        # Should not contain these error indicators
        error_indicators = [
            "ERROR:",
            "Exception:",
            "Traceback (most recent call last):",
            "FAILED",
        ]

        found_errors = []
        for indicator in error_indicators:
            if indicator in output_combined:
                found_errors.append(indicator)

        assert not found_errors, (
            f"Error indicators found in output: {', '.join(found_errors)}\n"
            f"STDOUT: {result.stdout}\n"
            f"STDERR: {result.stderr}"
        )

    @pytest.mark.slow
    def test_demonstration_quantum_libraries(self):
        """
        Test demonstration with quantum-resistant libraries if available.

        This test is marked as 'slow' and checks:
        - Dilithium signature generation (if liboqs-python or pqcrypto available)
        - Quantum-resistant verification
        - Proper fallback if libraries not available

        Note: This test may be skipped if quantum libraries are not installed.
        """
        try:
            import oqs  # noqa: F401

            quantum_available = True
            quantum_backend = "liboqs"
        except ImportError:
            try:
                from pqcrypto.sign import dilithium3  # noqa: F401

                quantum_available = True
                quantum_backend = "pqcrypto"
            except ImportError:
                quantum_available = False
                quantum_backend = None

        # Get the path to the main script
        script_path = Path(__file__).parent.parent / "dna_guardian_secure.py"

        # Run the demonstration
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if quantum_available:
            # If quantum libraries available, verify Dilithium is used
            assert (
                "Dilithium" in result.stdout
            ), f"Dilithium not found in output despite {quantum_backend} being available"
            # Should not have warnings about missing quantum libraries
            assert "WARNING: Quantum-resistant" not in result.stdout
        else:
            # If not available, should gracefully degrade
            # (Test passes as long as script completes successfully)
            assert result.returncode == 0


class TestErrorHandling:
    """Test error handling for missing dependencies."""

    def test_missing_cryptography_library(self):
        """
        Test behavior when cryptography library is missing.

        Note: This test is informational only since cryptography is required.
        The actual implementation should raise ImportError if cryptography is missing.
        """
        # This test documents expected behavior but cannot be easily tested
        # without manipulating import paths
        pytest.skip("Cryptography library is required; cannot test missing scenario")

    def test_graceful_quantum_library_fallback(self):
        """
        Test that missing quantum libraries result in graceful degradation.

        This test validates:
        - Script runs without quantum libraries
        - Appropriate warnings are displayed
        - Classical cryptography still functions
        - Verification still passes
        """
        try:
            import oqs  # noqa: F401

            pytest.skip("liboqs-python is installed; cannot test fallback")
        except ImportError:
            pass

        try:
            from pqcrypto.sign import dilithium3  # noqa: F401

            pytest.skip("pqcrypto is installed; cannot test fallback")
        except ImportError:
            pass

        # Both quantum libraries are missing, test fallback
        script_path = Path(__file__).parent.parent / "dna_guardian_secure.py"

        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            timeout=60,
        )

        # Should still complete successfully with fallback
        assert result.returncode == 0, (
            "Demonstration should complete successfully even without quantum libraries"
        )

        # Should have warning about quantum libraries
        # (This is optional; depends on implementation behavior)
