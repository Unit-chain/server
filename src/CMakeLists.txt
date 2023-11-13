cmake_minimum_required(VERSION 3.26)
project(tcpSocketTest)

set(CMAKE_CXX_STANDARD 20)

find_package(Boost REQUIRED COMPONENTS json log)
find_package(OpenSSL REQUIRED)

include_directories(
        utils
        server
)

add_definitions(
        -DDEBUG=0
        -DDEBUG_HEADERS=0
        -DDEBUG_SSL_HANDSHAKE=0
        -DDEBUG_ON_RECEIVE=0
        -DDEBUG_ON_FRAME=0
        -DDEBUG_FRAME_CALLBACK=0
        -DDEBUG_CHUNK_RECEIVED=0
)

add_executable(tcpSocketTest main.cpp
        session/HttpSession.cpp
        session/HttpSession.h
        session/SessionManager.cpp
        session/SessionManager.h
        utils/ssl/CTX_util.h
        session/HttpSessionException.cpp
        session/HttpSessionException.h
        server/data/HttpRequest.cpp
        server/data/HttpRequest.h
        server/data/HttpResponse.cpp
        server/data/HttpResponse.h
)

target_link_libraries(${PROJECT_NAME}
        OpenSSL::SSL
        Boost::json
        Boost::boost
        Boost::log
        /usr/local/lib/libnghttp2.a
)