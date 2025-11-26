# Ava Guardian Build Instructions

## Document Information

| Property | Value |
|----------|-------|
| Document Version | 1.0.0 |
| Last Updated | 2025-11-26 |
| Applies To | Ava Guardian v1.0.0+ |

---

## Overview

This document provides comprehensive build instructions for the Ava Guardian quantum-resistant cryptographic protection system. The system supports multiple build configurations including pure Python, Python with C extensions, and standalone C library builds.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Prerequisites](#prerequisites)
3. [Building](#building)
4. [Testing](#testing)
5. [Installation](#installation)
6. [Performance Optimization](#performance-optimization)
7. [Cross-Compilation](#cross-compilation)
8. [Docker Build](#docker-build)
9. [Troubleshooting](#troubleshooting)

---

## Quick Start

For users who want to get started quickly with default settings:

```bash
# Clone repository
git clone https://github.com/Steel-SecAdv-LLC/Ava-Guardian.git
cd Ava-Guardian

# Install dependencies
pip install -r requirements-dev.txt

# Build everything
make all

# Run tests
make test

# Install
make install
```

---

## Prerequisites

### Required Dependencies

| Dependency | Minimum Version | Purpose |
|------------|-----------------|---------|
| Python | 3.8 | Runtime environment |
| C Compiler | GCC 9+ / Clang 10+ / MSVC 2019+ | C library compilation |
| CMake | 3.15 | Build system |
| OpenSSL | 1.1.1 | Cryptographic primitives |

### Optional Dependencies

| Dependency | Minimum Version | Purpose |
|------------|-----------------|---------|
| Cython | 0.29.30 | Optimized Python extensions |
| NumPy | 1.24 | Mathematical operations |
| liboqs | 0.8 | Reference PQC implementations |
| Docker | 20.10 | Containerized deployment |
| Doxygen | 1.9 | C API documentation |
| Sphinx | 4.0 | Python API documentation |

### Platform-Specific Setup

#### Linux (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    python3-dev \
    python3-pip \
    git

# Optional: Install Cython and NumPy
pip3 install Cython numpy scipy
```

#### macOS

```bash
# Install Xcode Command Line Tools
xcode-select --install

# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install cmake openssl python@3.11

# Optional: Install Cython and NumPy
pip3 install Cython numpy scipy
```

#### Windows

1. Install Visual Studio 2019+ with C++ tools
2. Install CMake: https://cmake.org/download/
3. Install Python 3.8+: https://www.python.org/downloads/
4. Install OpenSSL: https://slproweb.com/products/Win32OpenSSL.html

```powershell
# Install Python dependencies
pip install Cython numpy scipy
```

## Building

### Method 1: Using Make (Linux/macOS)

```bash
# Build C library
make c

# Build Python extensions
make python

# Build everything
make all
```

### Method 2: Manual CMake Build

```bash
# Create build directory
mkdir build
cd build

# Configure
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DAVA_BUILD_SHARED=ON \
    -DAVA_BUILD_STATIC=ON \
    -DAVA_ENABLE_AVX2=ON

# Build
cmake --build . --config Release -j$(nproc)

# Run tests
ctest --output-on-failure
```

### Method 3: Python Setup.py

```bash
# Build and install in development mode
python3 setup.py develop

# Build extensions in-place
python3 setup.py build_ext --inplace

# Create distribution packages
python3 setup.py sdist bdist_wheel
```

### Build Options

CMake options can be set with `-D<OPTION>=<VALUE>`:

| Option | Default | Description |
|--------|---------|-------------|
| `AVA_BUILD_SHARED` | ON | Build shared library (.so/.dylib/.dll) |
| `AVA_BUILD_STATIC` | ON | Build static library (.a/.lib) |
| `AVA_BUILD_TESTS` | ON | Build test suite |
| `AVA_BUILD_EXAMPLES` | ON | Build example programs |
| `AVA_ENABLE_SIMD` | ON | Enable SIMD optimizations |
| `AVA_ENABLE_AVX2` | ON | Enable AVX2 instructions |
| `AVA_ENABLE_SANITIZERS` | OFF | Enable ASan/UBSan |
| `AVA_ENABLE_LTO` | ON | Enable link-time optimization |

Environment variables for Python build:

| Variable | Effect |
|----------|--------|
| `AVA_NO_CYTHON=1` | Disable Cython (use pure Python) |
| `AVA_NO_C_EXTENSIONS=1` | Disable C extensions |
| `AVA_DEBUG=1` | Enable debug symbols |
| `AVA_COVERAGE=1` | Enable coverage instrumentation |

## Testing

### C Tests

```bash
# Using Make
make test-c

# Using CMake directly
cd build
ctest --output-on-failure

# Run specific test
./build/bin/test_consttime
./build/bin/test_core
```

### Python Tests

```bash
# Using Make
make test-python

# Using pytest directly
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=ava_guardian --cov-report=html

# Run benchmarks
pytest tests/ --benchmark-only
```

### Running Examples

```bash
# C example
./build/bin/simple_example

# Python examples
python3 ava_guardian_monitor_demo.py
python3 benchmark_suite.py
```

## Installation

### System-Wide Installation

```bash
# Linux/macOS
sudo make install

# Or using CMake directly
cd build
sudo cmake --install .

# Python package
pip3 install .
```

### Development Installation

```bash
# Install in editable mode
pip3 install -e ".[dev,all]"

# Or using Make
make dev-install
```

### Verify Installation

```bash
# Check C library
pkg-config --modversion ava_guardian

# Check Python package
python3 -c "import ava_guardian; print(ava_guardian.__version__)"

# Run example
python3 -c "from ava_guardian import AvaEquationEngine; print('✓ Installed')"
```

## Performance Optimization

### Build for Maximum Performance

```bash
# C library with aggressive optimization
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DAVA_ENABLE_LTO=ON \
    -DAVA_ENABLE_AVX2=ON \
    -DCMAKE_C_FLAGS="-O3 -march=native -flto"

# Python with Cython
AVA_DEBUG=0 python3 setup.py build_ext --inplace
```

### Benchmark

```bash
# Run comprehensive benchmarks
make benchmark

# Profile specific operations
python3 -m cProfile -o profile.stats benchmark_suite.py
python3 -c "import pstats; pstats.Stats('profile.stats').sort_stats('cumulative').print_stats(20)"
```

## Troubleshooting

### "CMake not found"

```bash
# Linux
sudo apt-get install cmake

# macOS
brew install cmake
```

### "OpenSSL not found"

```bash
# Linux
sudo apt-get install libssl-dev

# macOS
brew install openssl
export OPENSSL_ROOT_DIR=/usr/local/opt/openssl
```

### "Cython compilation failed"

```bash
# Disable Cython and use pure Python
AVA_NO_CYTHON=1 python3 setup.py build_ext
```

### "AVX2 not supported"

```bash
# Disable AVX2
cmake .. -DAVA_ENABLE_AVX2=OFF
```

### Link errors on macOS

```bash
# Ensure correct OpenSSL path
export LDFLAGS="-L/usr/local/opt/openssl/lib"
export CPPFLAGS="-I/usr/local/opt/openssl/include"
```

## Cross-Compilation

### For ARM64 (e.g., Raspberry Pi, AWS Graviton)

```bash
cmake .. \
    -DCMAKE_SYSTEM_NAME=Linux \
    -DCMAKE_SYSTEM_PROCESSOR=aarch64 \
    -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc \
    -DAVA_ENABLE_AVX2=OFF
```

### For embedded systems (RISC-V)

```bash
cmake .. \
    -DCMAKE_TOOLCHAIN_FILE=../cmake/riscv-toolchain.cmake \
    -DAVA_BUILD_SHARED=OFF \
    -DAVA_ENABLE_SIMD=OFF
```

## Docker Build

```bash
# Build image
docker build -t ava-guardian:latest -f docker/Dockerfile .

# Run tests in container
docker run --rm ava-guardian:latest make test

# Interactive shell
docker run --rm -it ava-guardian:latest bash
```

---

## Related Documentation

| Document | Description |
|----------|-------------|
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development guidelines and contribution process |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System design and architectural decisions |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Production deployment procedures |
| [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md) | Security proofs and cryptographic analysis |

---

## Support

For technical issues and questions:

| Channel | Purpose |
|---------|---------|
| GitHub Issues | Bug reports and feature requests |
| Email: steel.sa.llc@gmail.com | Security vulnerabilities and private inquiries |

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-11-26 | Initial professional release |

---

Copyright 2025 Steel Security Advisors LLC. Licensed under Apache License 2.0.
