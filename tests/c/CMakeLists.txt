# C Tests CMakeLists.txt

# Test for constant-time operations
add_executable(test_consttime test_consttime.c)
if(AVA_BUILD_SHARED)
    target_link_libraries(test_consttime ava_guardian_shared)
else()
    target_link_libraries(test_consttime ava_guardian_static)
endif()

add_test(NAME ConstantTimeOperations COMMAND test_consttime)

# Test for core functionality
add_executable(test_core test_core.c)
if(AVA_BUILD_SHARED)
    target_link_libraries(test_core ava_guardian_shared)
else()
    target_link_libraries(test_core ava_guardian_static)
endif()

add_test(NAME CoreFunctionality COMMAND test_core)
