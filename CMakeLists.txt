cmake_minimum_required(VERSION 3.10)
project(MyCrowApp)

set(CMAKE_CXX_STANDARD 17)

add_executable(my_app main.cpp)

# Add Crow headers
include_directories(C:/Users/andre/my_crow_app/Crow/include)

# Link Boost and OpenSSL from vcpkg
find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)

target_link_libraries(my_app PRIVATE Boost::boost OpenSSL::SSL OpenSSL::Crypto ws2_32)
