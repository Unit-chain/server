//
// Created by Kirill Zhukov on 03.11.2023.
//

#include "HttpSessionException.h"

const char *StreamNotFound::what() const noexcept {
    return message.c_str();
}