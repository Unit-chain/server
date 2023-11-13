//
// Created by Kirill Zhukov on 10.11.2023.
//

#ifndef TCPSOCKETTEST_HTTPRESPONSE_H
#define TCPSOCKETTEST_HTTPRESPONSE_H
#include <iostream>
#include "boost/json.hpp"

namespace unit::server {
    namespace data {
        class HttpResponse {
        public:
            explicit HttpResponse(int32_t stream_id);
        public:
            std::string json_response;
            size_t read_offset = 0;

        private:
            const int32_t stream_id;
        };
    } // data
} // unit::server

#endif //TCPSOCKETTEST_HTTPRESPONSE_H
