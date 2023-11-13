//
// Created by Kirill Zhukov on 31.10.2023.
//

#include "SessionManager.h"

void SessionManager::start_session(boost::asio::ip::tcp::socket socket) {
    auto session = std::make_shared<HttpSession>(std::move(socket), this->key_file_path, this->cert_file_path);
    sessions_.insert(session);
    session->start();
}

void SessionManager::remove_session(const std::shared_ptr<HttpSession>& session) {
    sessions_.erase(session);
}

SessionManager::SessionManager(const std::string &key_file, const std::string &cert_file) : key_file_path(key_file), cert_file_path(cert_file) {}
