cmake_minimum_required (VERSION 3.25)

project (lichat)

#
# Dependencies
#
find_package(ICU REQUIRED COMPONENTS uc)
find_package(unofficial-sodium CONFIG REQUIRED)
set(CURSES_NEED_WIDE TRUE)
find_package(Curses REQUIRED)

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

add_executable(client
  "client.cpp"
)

target_compile_definitions(client PUBLIC NCURSES_WIDECHAR)

set_property(TARGET client PROPERTY CXX_STANDARD 20)
set_property(TARGET client PROPERTY CXX_STANDARD_REQUIRED ON)

target_include_directories(client PUBLIC
        ${NCURSES_INCLUDE_DIR}/ncursesw
)

target_link_libraries(client
    PUBLIC
    unofficial-sodium::sodium
    ICU::uc
    ${CURSES_LIBRARIES}
)

###################################################################################################
#
# Server
#
###################################################################################################

add_executable(server
  "server.cpp"
 )
 
set_property(TARGET server PROPERTY CXX_STANDARD 20)
set_property(TARGET server PROPERTY CXX_STANDARD_REQUIRED ON)

target_link_libraries(server
  PUBLIC
  unofficial-sodium::sodium
)

###################################################################################################