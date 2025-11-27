# Building Ava Guardian C API

This document describes how to build the Ava Guardian C library with liboqs integration
for native post-quantum cryptography support.

## Prerequisites

### liboqs Installation

The C API requires [liboqs](https://github.com/open-quantum-safe/liboqs) for PQC operations.

#### Ubuntu/Debian
```bash
# Install build dependencies
sudo apt-get update
sudo apt-get install -y cmake gcc ninja-build libssl-dev

# Option 1: Install from package (if available)
sudo apt-get install -y liboqs-dev

# Option 2: Build from source
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DBUILD_SHARED_LIBS=ON ..
ninja
sudo ninja install
sudo ldconfig
```

#### macOS
```bash
# Using Homebrew
brew install liboqs

# Or build from source
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DBUILD_SHARED_LIBS=ON ..
make -j$(sysctl -n hw.ncpu)
sudo make install
```

#### Windows
```powershell
# Using vcpkg
vcpkg install liboqs

# Or build from source with Visual Studio
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -G "Visual Studio 17 2022" -A x64 ..
cmake --build . --config Release
cmake --install . --config Release
```

## Building Ava Guardian C Library

### Standard Build (without liboqs)

```bash
cd src/c
gcc -c -fPIC -I../../include ava_core.c ava_kyber.c ava_consttime.c
ar rcs libava_guardian.a *.o
```

### Build with liboqs Integration

```bash
cd src/c

# Compile with liboqs support
gcc -c -fPIC -DAVA_USE_LIBOQS -I../../include \
    $(pkg-config --cflags liboqs) \
    ava_core.c ava_kyber.c ava_consttime.c

# Create static library
ar rcs libava_guardian.a *.o

# Or create shared library
gcc -shared -o libava_guardian.so *.o \
    $(pkg-config --libs liboqs)
```

### CMake Build (Recommended)

Create a `CMakeLists.txt` in the project root:

```cmake
cmake_minimum_required(VERSION 3.14)
project(ava_guardian VERSION 1.0.0 LANGUAGES C)

option(AVA_USE_LIBOQS "Build with liboqs support" ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find liboqs if enabled
if(AVA_USE_LIBOQS)
    find_package(liboqs REQUIRED)
    add_compile_definitions(AVA_USE_LIBOQS)
endif()

# Source files
set(AVA_SOURCES
    src/c/ava_core.c
    src/c/ava_kyber.c
    src/c/ava_consttime.c
)

# Static library
add_library(ava_guardian_static STATIC ${AVA_SOURCES})
target_include_directories(ava_guardian_static PUBLIC include)
if(AVA_USE_LIBOQS)
    target_link_libraries(ava_guardian_static PRIVATE OQS::oqs)
endif()

# Shared library
add_library(ava_guardian SHARED ${AVA_SOURCES})
target_include_directories(ava_guardian PUBLIC include)
if(AVA_USE_LIBOQS)
    target_link_libraries(ava_guardian PRIVATE OQS::oqs)
endif()

# Install targets
install(TARGETS ava_guardian ava_guardian_static
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)
install(FILES include/ava_guardian.h DESTINATION include)
```

Then build:

```bash
mkdir build && cd build
cmake -DAVA_USE_LIBOQS=ON ..
make -j$(nproc)
sudo make install
```

## Verifying the Build

### Test liboqs Integration

```c
// test_liboqs.c
#include <stdio.h>
#include "ava_guardian.h"

int main() {
    printf("Ava Guardian v%s\n", ava_version_string());

    // Initialize ML-DSA-65 context
    ava_context_t* ctx = ava_context_init(AVA_ALG_ML_DSA_65);
    if (!ctx) {
        printf("ERROR: Failed to initialize context\n");
        return 1;
    }

    // Generate keypair
    uint8_t pk[AVA_ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk[AVA_ML_DSA_65_SECRET_KEY_BYTES];

    ava_error_t err = ava_keypair_generate(ctx, pk, sizeof(pk), sk, sizeof(sk));
    if (err == AVA_SUCCESS) {
        printf("SUCCESS: ML-DSA-65 keypair generated\n");
    } else if (err == AVA_ERROR_NOT_IMPLEMENTED) {
        printf("INFO: liboqs not linked (expected without AVA_USE_LIBOQS)\n");
    } else {
        printf("ERROR: Keypair generation failed: %d\n", err);
    }

    ava_context_free(ctx);
    return 0;
}
```

Compile and run:

```bash
# Without liboqs
gcc -I./include test_liboqs.c -L./build -lava_guardian -o test_liboqs
./test_liboqs

# With liboqs
gcc -I./include test_liboqs.c -L./build -lava_guardian -loqs -o test_liboqs
./test_liboqs
```

## Supported Algorithms

When built with `AVA_USE_LIBOQS`, the following algorithms are available:

| Algorithm | liboqs Name | Key Sizes |
|-----------|-------------|-----------|
| ML-DSA-65 (Dilithium3) | `OQS_SIG_alg_ml_dsa_65` | PK: 1952, SK: 4032, Sig: 3309 |
| ML-KEM-1024 (Kyber-1024) | `OQS_KEM_alg_ml_kem_1024` | PK: 1568, SK: 3168, CT: 1568 |
| SPHINCS+-256f | `OQS_SIG_alg_sphincs_sha2_256f_simple` | PK: 64, SK: 128, Sig: 49856 |

Ed25519 is not provided by liboqs and returns `AVA_ERROR_NOT_IMPLEMENTED`.
Use the Python API for Ed25519 operations.

## Troubleshooting

### "liboqs not found"
Ensure liboqs is installed and pkg-config can find it:
```bash
pkg-config --exists liboqs && echo "Found" || echo "Not found"
pkg-config --cflags --libs liboqs
```

### "undefined reference to OQS_*"
Ensure you're linking against liboqs:
```bash
gcc ... -loqs
```

### Build warnings about unused functions
The polynomial arithmetic foundations (poly_add, poly_sub, etc.) are placeholders
for potential future native implementations. They generate unused function warnings
which are suppressed with:
```c
#pragma GCC diagnostic ignored "-Wunused-function"
```

## Python Integration

For most users, the Python API is recommended:

```bash
pip install ava-guardian[quantum]
```

This installs the `oqs` Python package which provides the same PQC functionality
without needing to compile the C library.
