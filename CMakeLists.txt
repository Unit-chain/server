cmake_minimum_required(VERSION 3.26)
project(unitServer)

set(CMAKE_CXX_STANDARD 20)

find_package(Boost REQUIRED COMPONENTS json)
find_package(OpenSSL REQUIRED)

add_executable(unitServer main.cpp)

target_link_libraries(${PROJECT_NAME}
        OpenSSL::SSL
        Boost::json
        Boost::boost
        /usr/local/lib/libnghttp2.a
)