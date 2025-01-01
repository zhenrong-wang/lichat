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

#
# Compiler options
#
#if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
#    add_compile_options(
#            -Wno-unknown-pragmas
#            -Wall
#            -Wextra
#            -Werror
#            -Wformat=2
#            -Wmissing-declarations
#            -Wunused
#            -Wcast-align
#            -Wfloat-equal
#            -Wformat-security
#            -Wconversion
#            -Wpedantic
#            -Wswitch
#            -Wno-error=switch-default
#    )
#elseif(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
#    add_compile_options(
#            /W4          # Warning level 4
#            /WX          # Treat warnings as errors
#            /permissive- # Strict standards compliance
#            /w14242     # 'identfier': conversion from 'type1' to 'type2', possible loss of data
#            /w14254     # 'operator': conversion from 'type1:field_bits' to 'type2:field_bits', possible loss of data
#            /w14263     # 'function': member function does not override any base class virtual member function
#            /w14265     # 'classname': class has virtual functions, but destructor is not virtual
#            /w14287     # 'operator': unsigned/negative constant mismatch
#            /we4289     # nonstandard extension used: 'variable': loop control variable declared in the for-loop is used outside the for-loop scope
#            /w14296     # 'operator': expression is always 'boolean_value'
#            /w14311     # 'variable': pointer truncation from 'type1' to 'type2'
#            /w14545     # expression before comma evaluates to a function which is missing an argument list
#            /w14546     # function call before comma missing argument list
#            /w14547     # 'operator': operator before comma has no effect; expected operator with side-effect
#            /w14549     # 'operator': operator before comma has no effect; did you intend 'operator'?
#            /w14555     # expression has no effect; expected expression with side-effect
#            /w14619     # pragma warning: there is no warning number 'number'
#            /w14640     # Enable warning on thread un-safe static member initialization
#            /w14826     # Conversion from 'type1' to 'type2' is sign-extended. This may cause unexpected runtime behavior.
#            /w14905     # wide string literal cast to 'LPSTR'
#            /w14906     # string literal cast to 'LPWSTR'
#            /w14928     # illegal copy-initialization; more than one user-defined conversion has been implicitly applied
#    )
#endif()

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