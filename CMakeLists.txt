cmake_minimum_required (VERSION 3.25)

project (lichat)

#
# Dependencies
#
find_package(ICU REQUIRED COMPONENTS uc)
find_package(unofficial-sodium CONFIG REQUIRED)
if(UNIX AND NOT APPLE)
    set(CURSES_NEED_WIDE TRUE)
    find_package(Curses REQUIRED)
endif()

#
# Platform libraries
#
if(WIN32)
    message(STATUS "Configuring build for Windows")
    set(PLATFORM_LIBS ws2_32)
elseif(UNIX AND NOT APPLE)
    message(STATUS "Configuring build for Linux")
    set(PLATFORM_LIBS Threads::Threads)
else()
    message(FATAL_ERROR "Unsupported platform")
endif()

###################################################################################################
#
# Client
#
###################################################################################################

add_executable(client
  "client.cpp"
)

if(UNIX AND NOT APPLE)
    target_compile_definitions(client PUBLIC NCURSES_WIDECHAR)
endif()

set_property(TARGET client PROPERTY CXX_STANDARD 20)
set_property(TARGET client PROPERTY CXX_STANDARD_REQUIRED ON)

target_link_libraries(client
    PUBLIC
    unofficial-sodium::sodium
    ICU::uc
)

if(UNIX AND NOT APPLE)
    target_include_directories(client PUBLIC
            ${NCURSES_INCLUDE_DIR}/ncursesw
    )
    target_link_libraries(client PUBLIC ${CURSES_LIBRARIES})
endif()

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