# Copyright 2025 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
#
# Makefile for Ava Guardian
#
# Quick build targets:
#   make all        - Build everything (C library + Python extensions)
#   make c          - Build C library only
#   make python     - Build Python package
#   make test       - Run all tests
#   make clean      - Clean build artifacts
#   make install    - Install library system-wide
#   make docker     - Build Docker image

.PHONY: all c python test clean install docker help

# Default target
all: c python

# Build C library with CMake
c:
	@echo "Building C library..."
	@mkdir -p build
	@cd build && cmake .. && $(MAKE)
	@echo "✓ C library built successfully"

# Build Python package with extensions
python:
	@echo "Building Python package..."
	@python3 setup.py build_ext --inplace
	@echo "✓ Python package built successfully"

# Run tests
test: test-c test-python

test-c: c
	@echo "Running C tests..."
	@cd build && ctest --output-on-failure
	@echo "✓ C tests passed"

test-python: python
	@echo "Running Python tests..."
	@pytest tests/ -v --cov=ava_guardian --cov-report=term-missing
	@echo "✓ Python tests passed"

# Run benchmarks
benchmark: python
	@echo "Running benchmarks..."
	@python3 benchmark_suite.py
	@pytest tests/ --benchmark-only

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf build/
	@rm -rf lib/
	@rm -rf *.so *.egg-info dist/ .eggs/
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete
	@find . -type f -name "*.pyo" -delete
	@find . -type f -name "*.c" -path "*/src/cython/*" -delete
	@echo "✓ Cleaned"

# Install system-wide
install: all
	@echo "Installing Ava Guardian..."
	@cd build && sudo $(MAKE) install
	@pip3 install -e .
	@echo "✓ Installed successfully"

# Development install
dev-install:
	@echo "Installing development dependencies..."
	@pip3 install -e ".[dev,all]"
	@echo "✓ Development environment ready"

# Format code
format:
	@echo "Formatting code..."
	@black ava_guardian/ tests/ *.py
	@isort ava_guardian/ tests/ *.py
	@echo "✓ Code formatted"

# Lint code
lint:
	@echo "Linting code..."
	@flake8 ava_guardian/ tests/ --max-line-length=100
	@mypy ava_guardian/ --ignore-missing-imports
	@echo "✓ Lint passed"

# Generate documentation
# Requires: sphinx from requirements-dev.txt (pip install -r requirements-dev.txt)
docs:
	@echo "Generating documentation..."
	@cd build && doxygen ../docs/Doxyfile
	@cd docs && sphinx-build -b html . _build/html
	@echo "✓ Documentation generated"
	@echo "  C API docs:      build/docs/html/index.html"
	@echo "  Python API docs: docs/_build/html/index.html"

# Build Docker image
docker:
	@echo "Building Docker image..."
	@docker build -t ava-guardian:latest -f docker/Dockerfile .
	@echo "✓ Docker image built"

# Create release distribution
dist: clean
	@echo "Creating distribution packages..."
	@python3 setup.py sdist bdist_wheel
	@echo "✓ Distribution packages created in dist/"

# Security audit
security-audit:
	@echo "Running security audit..."
	@pip-audit
	@bandit -r ava_guardian/ -ll
	@echo "✓ Security audit complete"

# Performance profiling
profile: python
	@echo "Profiling performance..."
	@python3 -m cProfile -o profile.stats benchmark_suite.py
	@python3 -c "import pstats; p = pstats.Stats('profile.stats'); p.sort_stats('cumulative'); p.print_stats(30)"

# Help
help:
	@echo "Ava Guardian ♱ Build System"
	@echo "============================"
	@echo ""
	@echo "Main targets:"
	@echo "  make all            - Build C library and Python extensions"
	@echo "  make c              - Build C library only"
	@echo "  make python         - Build Python package"
	@echo "  make test           - Run all tests"
	@echo "  make benchmark      - Run performance benchmarks"
	@echo "  make clean          - Remove build artifacts"
	@echo "  make install        - Install system-wide"
	@echo "  make dev-install    - Install development environment"
	@echo ""
	@echo "Development targets:"
	@echo "  make format         - Format code with black/isort"
	@echo "  make lint           - Lint code with flake8/mypy"
	@echo "  make docs           - Generate API documentation"
	@echo "  make security-audit - Run security checks"
	@echo "  make profile        - Profile performance"
	@echo ""
	@echo "Deployment targets:"
	@echo "  make docker         - Build Docker image"
	@echo "  make dist           - Create release distributions"
	@echo ""
