# C Examples CMakeLists.txt

# Simple example demonstrating basic usage
add_executable(simple_example simple_example.c)
if(AVA_BUILD_SHARED)
    target_link_libraries(simple_example ava_guardian_shared)
else()
    target_link_libraries(simple_example ava_guardian_static)
endif()

# Install examples
install(TARGETS simple_example
    RUNTIME DESTINATION bin/examples
)
