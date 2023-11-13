//
// Created by Kirill Zhukov on 10.11.2023.
//

#include "HttpRequest.h"

unit::server::data::HttpRequest::HttpRequest(bool isFinished, const std::vector<unsigned char> &data, int32_t stream_id)
        : finalized(isFinished), data(data), stream_id(stream_id) {}

unit::server::data::HttpRequest::HttpRequest(int32_t stream_id) : finalized(false), stream_id(stream_id) {}

int32_t unit::server::data::HttpRequest::getStreamId() const {
    return stream_id;
}

void unit::server::data::HttpRequest::setIsFinished(bool isFinished) {
    this->finalized = isFinished;
}

const std::vector<unsigned char> &unit::server::data::HttpRequest::getData() {
    return data;
}

bool unit::server::data::HttpRequest::isFinished() const {
    return false;
}
