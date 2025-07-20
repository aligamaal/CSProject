cmake_minimum_required(VERSION 3.10)
project(MyCrowApp)

set(CMAKE_CXX_STANDARD 17)

# Core source files
set(CORE_SOURCES
    "Source Files/main.cpp"
    "Source Files/AuthManager.cpp"
    "Source Files/CORSMiddleware.cpp"
    "Source Files/Utils.cpp"
    "Source Files/User.cpp"
)

# Verify core files exist
foreach(src ${CORE_SOURCES})
    if(NOT EXISTS ${src})
        message(WARNING "Core source file ${src} not found!")
    endif()
endforeach()

# Optional: Include any additional .cpp files that might be added later
file(GLOB EXTRA_SOURCES "Source Files/*.cpp")
list(REMOVE_ITEM EXTRA_SOURCES ${CORE_SOURCES})  # Remove already listed files

# Create executable with both core and extra sources
add_executable(my_app ${CORE_SOURCES} ${EXTRA_SOURCES})

# Platform-independent Crow include path
set(CROW_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/Crow/include")
if(NOT EXISTS "${CROW_INCLUDE_DIR}/crow_all.h")
    # Fallback to relative path if not found at absolute path
    set(CROW_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/../Crow/include")
    if(NOT EXISTS "${CROW_INCLUDE_DIR}/crow_all.h")
        message(FATAL_ERROR "Crow headers not found at ${CROW_INCLUDE_DIR}")
    endif()
endif()

# Find required packages
find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(
    "${CMAKE_SOURCE_DIR}/Header Files"
    "${CROW_INCLUDE_DIR}"
)

# Link libraries with platform-specific handling
target_link_libraries(my_app PRIVATE 
    Boost::boost 
    OpenSSL::SSL 
    OpenSSL::Crypto
)

# Windows-specific libraries
if(WIN32)
    target_link_libraries(my_app PRIVATE ws2_32)
endif()
