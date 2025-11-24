# Ava Guardian ♱ Build Instructions

Complete guide for building the multi-language Ava Guardian PQC system.

## Table of Contents

- [Quick Start](#quick-start)
- [Prerequisites](#prerequisites)
- [Building](#building)
- [Testing](#testing)
- [Installation](#installation)
- [Troubleshooting](#troubleshooting)

## Quick Start

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

## Prerequisites

### Required

- **Python**: 3.8 or higher
- **C Compiler**: GCC 9+, Clang 10+, or MSVC 2019+
- **CMake**: 3.15 or higher
- **OpenSSL**: 1.1.1 or higher

### Optional (for full features)

- **Cython**: 3.0+ (for optimized Python extensions)
- **NumPy**: 1.24+ (for mathematical operations)
- **liboqs**: 0.8+ (for reference PQC implementations)
- **Docker**: For containerized deployment
- **Doxygen**: For C API documentation
- **Sphinx**: For Python API documentation

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

## Next Steps

- See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines
- See [ARCHITECTURE.md](ARCHITECTURE.md) for system design
- See [DEPLOYMENT.md](DEPLOYMENT.md) for production deployment
- See [API documentation](docs/api/) for API reference

## Support

For issues and questions:
- GitHub Issues: https://github.com/Steel-SecAdv-LLC/Ava-Guardian/issues
- Email: steel.secadv.llc@outlook.com
