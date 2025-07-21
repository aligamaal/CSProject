cmake_minimum_required(VERSION 3.10)
project(MyCrowApp)

set(CMAKE_CXX_STANDARD 17)

# Source files
add_executable(my_app 
    "Source Files/main.cpp"
    "Source Files/AuthManager.cpp"
    "Source Files/CORSMiddleware.cpp"
    "Source Files/Utils.cpp" 
    "Source Files/User.cpp"
    "Source Files/AVLTree.cpp"
    "Source Files/SocialNetworkManager.cpp"
)

# Include directories
include_directories(
    "Header Files"
    "${CMAKE_SOURCE_DIR}/thirdparty/Crow/include" 
)

# Find dependencies
find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)

# Link libraries - platform specific
target_link_libraries(my_app PRIVATE 
    Boost::boost 
    OpenSSL::SSL 
    OpenSSL::Crypto
)

# Windows-specific libraries
if(WIN32)
    target_link_libraries(my_app PRIVATE ws2_32)
endif()
