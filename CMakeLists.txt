cmake_minimum_required(VERSION 3.10)
project(ModbusMITM LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Set common paths for CMake to find packages
list(APPEND CMAKE_PREFIX_PATH /usr/local /usr)

# Find PkgConfig for finding other libraries
find_package(PkgConfig REQUIRED)

# Find PcapPlusPlus using pkg-config
pkg_check_modules(PCAPPLUSPLUS REQUIRED PcapPlusPlus)
# If PcapPlusPlus.pc is not found or does not provide the necessary targets,
# find_package(PcapPlusPlus REQUIRED) would be the fallback, but it has been failing.

# Find libnetfilter_queue using pkg-config
pkg_check_modules(NETFILTER_QUEUE REQUIRED libnetfilter_queue)

# Add executable
add_executable(mitm_tool main.cpp)

# Link libraries
# Using variables from pkg_check_modules
target_link_libraries(mitm_tool
    PRIVATE
    ${PCAPPLUSPLUS_LIBRARIES}
    ${NETFILTER_QUEUE_LIBRARIES}
)

# Add include directories
# Using variables from pkg_check_modules
target_include_directories(mitm_tool
    PRIVATE
    ${PCAPPLUSPLUS_INCLUDE_DIRS}
    ${NETFILTER_QUEUE_INCLUDE_DIRS}
)

# Ensure C++17 is used
# target_compile_features(mitm_tool PRIVATE cxx_std_17) # Redundant if CMAKE_CXX_STANDARD is set globally

install(TARGETS mitm_tool DESTINATION bin)
