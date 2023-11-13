//
// Created by Kirill Zhukov on 03.11.2023.
//

#ifndef TCPSOCKETTEST_HTTPSESSIONEXCEPTION_H
#define TCPSOCKETTEST_HTTPSESSIONEXCEPTION_H

#include <exception>
#include <string>
#include <utility>

class StreamNotFound : public std::exception {
private:
    std::string message;

public:
    // Constructor (C++11 onward)
    explicit StreamNotFound(std::string msg) : message(std::move(msg)) {}

    // Override the what() method from the base class
    [[nodiscard]] const char* what() const noexcept override;
};

#endif //TCPSOCKETTEST_HTTPSESSIONEXCEPTION_H
