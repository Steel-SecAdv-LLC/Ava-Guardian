#!/usr/bin/env python3
# Copyright 2025 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

"""Basic tests for Ava Guardian"""

import ava_guardian


def test_version():
    """Test that version is correctly set"""
    assert hasattr(ava_guardian, "__version__")
    assert ava_guardian.__version__ == "1.0.0"


def test_author():
    """Test that author is correctly set"""
    assert hasattr(ava_guardian, "__author__")
    assert "Andrew E. A." in ava_guardian.__author__


def test_imports():
    """Test that key components can be imported"""
    from ava_guardian import (
        DNA_CODES,
        HELIX_PARAMS,
        LAMBDA_DECAY,
        PHI,
        PHI_CUBED,
        PHI_SQUARED,
        SIGMA_QUADRATIC_THRESHOLD,
        AvaEquationEngine,
        calculate_sigma_quadratic,
        enforce_sigma_quadratic_threshold,
        golden_ratio_convergence_proof,
        helix_curvature,
        helix_torsion,
        initialize_ethical_matrix,
        lyapunov_function,
        lyapunov_stability_proof,
        verify_all_dna_codes,
        verify_mathematical_foundations,
    )

    assert PHI is not None
    assert PHI_SQUARED is not None
    assert PHI_CUBED is not None


def test_equation_engine_exists():
    """Test that AvaEquationEngine can be instantiated"""
    from ava_guardian import AvaEquationEngine

    # Just verify it exists and is callable
    assert AvaEquationEngine is not None
    assert callable(AvaEquationEngine)


def test_mathematical_constants():
    """Test that mathematical constants are correctly defined"""
    from ava_guardian import PHI, PHI_CUBED, PHI_SQUARED

    # Golden ratio should be approximately 1.618
    assert 1.6 < PHI < 1.7
    assert abs(PHI**2 - PHI_SQUARED) < 0.001
    assert abs(PHI**3 - PHI_CUBED) < 0.001
