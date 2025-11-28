# C Tests CMakeLists.txt

# Helper macro for adding tests
macro(add_ava_test test_name test_source)
    add_executable(${test_name} ${test_source})
    if(AVA_BUILD_SHARED)
        target_link_libraries(${test_name} ava_guardian_shared)
    else()
        target_link_libraries(${test_name} ava_guardian_static)
    endif()
    add_test(NAME ${test_name} COMMAND ${test_name})
endmacro()

# Core tests
add_ava_test(test_consttime test_consttime.c)
add_ava_test(test_core test_core.c)

# Cryptographic primitive tests
add_ava_test(test_sha3 test_sha3.c)
add_ava_test(test_hkdf test_hkdf.c)
add_ava_test(test_ed25519 test_ed25519.c)

# Performance benchmark (not added to ctest - run manually)
add_executable(test_benchmark test_benchmark.c)
if(AVA_BUILD_SHARED)
    target_link_libraries(test_benchmark ava_guardian_shared)
else()
    target_link_libraries(test_benchmark ava_guardian_static)
endif()
