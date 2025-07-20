cmake_minimum_required(VERSION 3.10)
project(MyCrowApp)

set(CMAKE_CXX_STANDARD 17)

# Source Files Configuration (Cross-Platform)
set(SOURCE_DIR "Source Files")  # Original name
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE_DIR}")
    set(SOURCE_DIR "src")  # Fallback to standard name
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE_DIR}")
        message(FATAL_ERROR "Source directory not found! Tried: 'Source Files' and 'src'")
    endif()
endif()

# Core source files (relative to SOURCE_DIR)
set(CORE_SOURCES
    "${SOURCE_DIR}/main.cpp"
    "${SOURCE_DIR}/AuthManager.cpp"
    "${SOURCE_DIR}/CORSMiddleware.cpp"
    "${SOURCE_DIR}/Utils.cpp"
    "${SOURCE_DIR}/User.cpp"
)

# Verify all core files exist
foreach(src ${CORE_SOURCES})
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${src}")
        message(WARNING "Missing source file: ${src}")
    endif()
endforeach()

# Auto-discover additional .cpp files
file(GLOB EXTRA_SOURCES "${SOURCE_DIR}/*.cpp")
list(REMOVE_ITEM EXTRA_SOURCES ${CORE_SOURCES})  # Avoid duplicates

# Try possible Crow locations (prioritize submodule)
set(CROW_PATHS_TO_TRY
    "${CMAKE_SOURCE_DIR}/thirdparty/Crow/include"  # Git submodule location
    "${CMAKE_SOURCE_DIR}/Crow/include"             # Manual install
    "${CMAKE_SOURCE_DIR}/../Crow/include"          # Adjacent directory
)

# Find crow_all.h
unset(CROW_INCLUDE_DIR CACHE)  # Clear any cached value
foreach(path ${CROW_PATHS_TO_TRY})
    if(EXISTS "${path}/crow.h" OR EXISTS "${path}/crow/crow.h")
        set(CROW_INCLUDE_DIR "${path}" CACHE PATH "Path to Crow headers")
        break()
    endif()
endforeach()

if(NOT CROW_INCLUDE_DIR)
    message(FATAL_ERROR "Crow headers not found! Tried:\n  ${CROW_PATHS_TO_TRY}")
else()
    message(STATUS "Found Crow headers at: ${CROW_INCLUDE_DIR}")
endif()

# Header Files Configuration

set(HEADER_DIR "Header Files")  # Original name
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${HEADER_DIR}")
    set(HEADER_DIR "include")  # Fallback to standard name
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${HEADER_DIR}")
        message(WARNING "Header directory not found! Tried: 'Header Files' and 'include'")
    endif()
endif()


# Create executable
add_executable(my_app ${CORE_SOURCES} ${EXTRA_SOURCES})

# Include directories
target_include_directories(my_app PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/${HEADER_DIR}"
    "${CROW_INCLUDE_DIR}"
)

# Find and link dependencies
find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)

target_link_libraries(my_app PRIVATE
    Boost::boost
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Windows-specific libraries
if(WIN32)
    target_link_libraries(my_app PRIVATE ws2_32)
endif()
