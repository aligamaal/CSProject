cmake_minimum_required(VERSION 3.10)
project(MyCrowApp)

set(CMAKE_CXX_STANDARD 17)

add_executable(my_app 
    "Source Files/main.cpp"
    "Source Files/AuthManager.cpp"        # Add this if it exists
    "Source Files/CORSMiddleware.cpp"     # Add this if it exists
    "Source Files/Utils.cpp" 
    "Source Files/User.cpp"
    "Source Files/AVLTree.cpp"
    "Source Files/SocialNetworkManager.cpp"              # Add this if getMimeType is here
    # Add any other .cpp files you have
)

# Add Crow headers
include_directories(C:/Users/andre/my_crow_app/Crow/include)

# Link Boost and OpenSSL from vcpkg
find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)

target_link_libraries(my_app PRIVATE Boost::boost OpenSSL::SSL OpenSSL::Crypto ws2_32)
include_directories("Header Files")
