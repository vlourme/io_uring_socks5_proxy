cmake_minimum_required(VERSION 3.16)

project(proxy
    LANGUAGES C CXX
)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_definitions(_GNU_SOURCE)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -D_GNU_SOURCE")

set(LINK_LIBURING ON CACHE BOOL "Use bundled liburing")

add_subdirectory(third_party/condy)
add_subdirectory(third_party/dotenv_cpp)
add_subdirectory(third_party/spdlog)

# ---- Your executable ----
add_executable(proxy
    src/main.cpp
)

find_library(MIMALLOC_LIBRARY NAMES mimalloc)

target_link_libraries(proxy
    PRIVATE mimalloc
    PRIVATE condy
    PRIVATE dotenv
    PRIVATE spdlog
)
