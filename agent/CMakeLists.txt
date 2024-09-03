cmake_minimum_required(VERSION 3.10)
project(QuantaShield-Agent)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)

# Add the executable, pointing to the correct main.cpp location
add_executable(QuantaShield-Agent src/main.cpp)

# Link the libpcap library manually
target_link_libraries(QuantaShield-Agent pcap)
