cmake_minimum_required(VERSION 3.10)
project(MyCrowApp)

set(CMAKE_CXX_STANDARD 17)

<<<<<<< HEAD
add_executable(my_app 
    "Source Files/main.cpp"
    "Source Files/AuthManager.cpp"        
    "Source Files/CORSMiddleware.cpp"   
    "Source Files/Utils.cpp" 
    "Source Files/User.cpp"
    "Source Files/AVLTree.cpp"
    "Source Files/SocialNetworkManager.cpp"             
    # Add any other .cpp files you have
=======
# Source Files Configuration (Cross-Platform)
set(SOURCE_DIR "Source Files")
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE_DIR}")
    set(SOURCE_DIR "src")
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE_DIR}")
        message(FATAL_ERROR "Source directory not found! Tried: 'Source Files' and 'src'")
    endif()
endif()

set(CORE_SOURCES
    "${SOURCE_DIR}/main.cpp"
    "${SOURCE_DIR}/AuthManager.cpp"
    "${SOURCE_DIR}/CORSMiddleware.cpp"
    "${SOURCE_DIR}/Utils.cpp"
    "${SOURCE_DIR}/User.cpp"
>>>>>>> ea73ec424d5d578ff3225c50c576b25177f6e6c5
)

foreach(src ${CORE_SOURCES})
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${src}")
        message(WARNING "Missing source file: ${src}")
    endif()
endforeach()

file(GLOB EXTRA_SOURCES "${SOURCE_DIR}/*.cpp")
list(REMOVE_ITEM EXTRA_SOURCES ${CORE_SOURCES})

# Crow Configuration - Case-sensitive check
set(CROW_PATHS_TO_TRY
    "${CMAKE_SOURCE_DIR}/thirdparty/crow/include"  
    "${CMAKE_SOURCE_DIR}/thirdparty/Crow/include"  
    "${CMAKE_SOURCE_DIR}/crow/include"
    "${CMAKE_SOURCE_DIR}/../crow/include"
)

unset(CROW_INCLUDE_DIR CACHE)
foreach(path ${CROW_PATHS_TO_TRY})
    if(EXISTS "${path}/crow.h")
        set(CROW_INCLUDE_DIR "${path}")
        break()
    endif()
endforeach()

if(NOT CROW_INCLUDE_DIR)
    message(FATAL_ERROR "Crow headers not found! Tried:\n  ${CROW_PATHS_TO_TRY}\n"
    "Please ensure:\n"
    "1. Git submodule is initialized: git submodule update --init\n"
    "2. Crow headers exist at thirdparty/crow/include/crow.h")
endif()
message(STATUS "Found Crow headers at: ${CROW_INCLUDE_DIR}")

# Header Files
set(HEADER_DIR "Header Files")
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${HEADER_DIR}")
    set(HEADER_DIR "include")
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${HEADER_DIR}")
        message(WARNING "Header directory not found! Tried: 'Header Files' and 'include'")
    endif()
endif()

add_executable(my_app ${CORE_SOURCES} ${EXTRA_SOURCES})

# Include directories 
target_include_directories(my_app PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/${HEADER_DIR}"
    ${CROW_INCLUDE_DIR}
)

find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)

target_link_libraries(my_app PRIVATE
    Boost::boost
    OpenSSL::SSL
    OpenSSL::Crypto
)

if(WIN32)
    target_link_libraries(my_app PRIVATE ws2_32)
endif()
