cmake_minimum_required (VERSION 3.25)

project (lichat)

#
# Dependencies
#
find_package(ICU REQUIRED COMPONENTS uc)

# Find SQLite3
find_package(PkgConfig REQUIRED)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)
message(STATUS "Using system SQLite3 via pkg-config")

# Try to find libsodium via vcpkg first, then fall back to pkg-config
find_package(unofficial-sodium CONFIG QUIET)
if(NOT unofficial-sodium_FOUND)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBSODIUM REQUIRED libsodium)
    message(STATUS "Using system libsodium via pkg-config")
    add_library(unofficial-sodium::sodium INTERFACE IMPORTED)
    target_include_directories(unofficial-sodium::sodium INTERFACE ${LIBSODIUM_INCLUDE_DIRS})
    target_link_libraries(unofficial-sodium::sodium INTERFACE ${LIBSODIUM_LIBRARIES})
    target_compile_options(unofficial-sodium::sodium INTERFACE ${LIBSODIUM_CFLAGS_OTHER})
else()
    message(STATUS "Using vcpkg libsodium")
endif()

#
# Platform libraries
#
message(STATUS "Configuring build for Linux")
set(PLATFORM_LIBS Threads::Threads)

#
# Compiler options
#
add_compile_options(
    -Wno-unknown-pragmas
    -Wall
    -Wextra
    -Werror
    -Wformat=2
    -Wmissing-declarations
    -Wunused
    -Wcast-align
    -Wfloat-equal
    -Wformat-security
    -Wconversion
    -Wpedantic
    -Wswitch
    -Wno-error=switch-default
)

###################################################################################################
#
# Client
#
###################################################################################################

# Find Qt6 (or Qt5)
find_package(Qt6 QUIET COMPONENTS Core Widgets)
if(Qt6_FOUND)
    set(QT_VERSION_MAJOR 6)
    message(STATUS "Found Qt6")
else()
    find_package(Qt5 5.15 REQUIRED COMPONENTS Core Widgets)
    set(QT_VERSION_MAJOR 5)
    message(STATUS "Found Qt5")
endif()

# Enable Qt MOC
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

add_executable(client
  "client.cpp"
  "lc_ui_qt.cpp"
  "lc_ui_qt.hpp"
)

set_property(TARGET client PROPERTY CXX_STANDARD 20)
set_property(TARGET client PROPERTY CXX_STANDARD_REQUIRED ON)

target_link_libraries(client
    PUBLIC
    unofficial-sodium::sodium
    ICU::uc
)

# Link Qt libraries
if(QT_VERSION_MAJOR EQUAL 6)
    target_link_libraries(client
        PUBLIC
        Qt6::Core
        Qt6::Widgets
    )
else()
    target_link_libraries(client
        PUBLIC
        Qt5::Core
        Qt5::Widgets
    )
endif()

###################################################################################################
#
# Server
#
###################################################################################################

add_executable(server
  "server.cpp"
  "lc_db.cpp"
 )
 
set_property(TARGET server PROPERTY CXX_STANDARD 20)
set_property(TARGET server PROPERTY CXX_STANDARD_REQUIRED ON)

target_link_libraries(server
  PUBLIC
  unofficial-sodium::sodium
  ${SQLITE3_LIBRARIES}
)
target_include_directories(server PUBLIC ${SQLITE3_INCLUDE_DIRS})

###################################################################################################