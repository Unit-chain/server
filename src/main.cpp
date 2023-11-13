#include <iostream>
#include "session/SessionManager.h"

int main() {
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::acceptor acceptor(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 8080));
    SessionManager manager = SessionManager("/Users/kirillzhukov/Downloads/server.key", "/Users/kirillzhukov/Downloads/server.pem");
    std::function<void()> do_accept;
    do_accept = [&]() {
        auto socket = std::make_shared<boost::asio::ip::tcp::socket>(io_context);
        acceptor.async_accept(*socket, [&, socket](boost::system::error_code ec) {
            if (!ec) {
                BOOST_LOG_TRIVIAL(info) << "Connection accepted.";
                manager.start_session(std::move(*socket));
            } else {
                BOOST_LOG_TRIVIAL(error) << "ERROR: " << ec.what();
            }
            do_accept();
        });
    };
    do_accept();
    io_context.run();

    return 0;
}
