cmake_minimum_required(VERSION 3.10)
project(Sniffer)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Source files
set(SOURCES
    src/main.cpp
    src/socket_manager.cpp
    src/packet_parser.cpp
    src/packet_structure.cpp
    src/http_parser.cpp
    src/packet_printer.cpp
)

# Include directories
include_directories(include)

# Executable
add_executable(sniffer ${SOURCES})

# Set capabilities for raw sockets after build (optional, requires manual execution)
add_custom_command(TARGET sniffer POST_BUILD
    COMMAND sudo setcap cap_net_raw=eip ${CMAKE_CURRENT_BINARY_DIR}/sniffer
    COMMENT "Applying raw socket permissions"
)
