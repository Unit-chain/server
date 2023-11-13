//
// Created by Kirill Zhukov on 31.10.2023.
//

#ifndef TCPSOCKETTEST_SESSIONMANAGER_H
#define TCPSOCKETTEST_SESSIONMANAGER_H

#include "set"
#include "memory"
#include "HttpSession.h"

class SessionManager {
public:
    SessionManager(const std::string &key_file, const std::string &cert_file);

    void start_session(boost::asio::ip::tcp::socket socket);

    void remove_session(const std::shared_ptr<HttpSession>& session);

private:
    std::set<std::shared_ptr<HttpSession>> sessions_{};
    const std::string key_file_path;
    const std::string cert_file_path;
};


#endif //TCPSOCKETTEST_SESSIONMANAGER_H
