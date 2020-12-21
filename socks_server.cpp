#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <utility>
#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>
#include <vector>
#include <array>

using boost::asio::ip::tcp;
using std::cerr;
using std::cout;
using std::endl;
using std::shared_ptr;
using std::string;

enum
{
    max_length = 1024
};
boost::asio::io_context io_context;

class session
    : public std::enable_shared_from_this<session>
{
public:
    session(std::shared_ptr<tcp::socket> read_sock, std::shared_ptr<tcp::socket> send_sock)
        : read_sock_(read_sock), send_sock_(send_sock) {}
    void start()
    {
        do_read();
    }

private:
    shared_ptr<tcp::socket> read_sock_;
    shared_ptr<tcp::socket> send_sock_;
    std::array<unsigned char, max_length> relay_data = {0};

    void do_read()
    {
        auto self(shared_from_this());
        relay_data = {0};
        read_sock_->async_read_some(boost::asio::buffer(relay_data, max_length),
                                    [this, self](boost::system::error_code ec, std::size_t length) {
                                        if (!ec)
                                        {
                                            do_write(length);
                                        }
                                        else
                                        {
                                            cout << "read error: " << ec.message() << endl;
                                            read_sock_->close();
                                            send_sock_->close();
                                        }
                                    });
    }

    void do_write(std::size_t length)
    {
        auto self(shared_from_this());
        boost::asio::async_write(*send_sock_, boost::asio::buffer(relay_data, length),
                                 [this, self](boost::system::error_code ec, std::size_t write_length) {
                                     if (!ec)
                                     {
                                        do_read();
                                     }
                                     else
                                     {
                                         cout << "write error: " << ec.message() << endl;
                                         read_sock_->close();
                                         send_sock_->close();
                                     }
                                 });
    }
};

bool firewall(u_char request[])
{
    std::ifstream conf("socks_conf");
    if (!conf.is_open())
    {
        cerr << "socks_conf not exist" << endl;
        return false;
    }
    string rule, mode, addr;
    string addr_seg[4];

    while (conf >> rule)
    {
        conf >> mode;
        conf >> addr;
        std::size_t pos;
        for (int i = 0; i < 4; i++)
        {
            pos = addr.find('.');
            if (pos != string::npos)
            {
                addr_seg[i] = addr.substr(0, pos);
                addr.erase(0, pos + 1);
            }
            else
                addr_seg[i] = addr.substr(0);
        }
        if ((mode == "c" && request[1] == 1) || (mode == "b" && request[1] == 2))
        {
            bool same_addr = true;
            for (int i = 0; i < 4; i++)
                if (addr_seg[i] != "*" && ((u_char)std::stoul(addr_seg[i]) != request[i + 4]))
                {
                    same_addr = false;
                    break;
                }
            if (same_addr)
                return true;
        }
    }
    return false;
}

void socks_protocol(shared_ptr<tcp::socket> cli_socket)
{
    tcp::endpoint ep;
    u_char request_[max_length] = {0};
    u_char reply_[8] = {0};

    cli_socket->read_some(boost::asio::buffer(request_));
    u_char vn = request_[0];
    u_char cd = request_[1];
    u_short dst_port = request_[2] << 8 | request_[3];
    string dst_ip = std::to_string(request_[4]) + "." + std::to_string(request_[5]) + "." + std::to_string(request_[6]) + "." + std::to_string(request_[7]);
    string usr_id = (char *)(request_ + 8);

    cout << dst_port << endl;
    if (vn != 4)
    {
        cerr << "Bad socks4 request\n";
        exit(0);
    }
    else if (cd != 1 && cd != 2)
    {
        cerr << "Bad socks4 request CD = " << cd << endl;
    }
    //socks4A
    if (request_[4] == 0 && request_[5] == 0 && request_[6] == 0 && request_[7] != 0)
    {
        string domain_name = (char *)(request_ + 8) + usr_id.length() + 1;
        tcp::resolver resolver_(io_context);
        boost::system::error_code ec;
        tcp::resolver::iterator ep_iter = resolver_.resolve(domain_name, std::to_string(dst_port), ec);
        if (!ec)
        {
            for (tcp::resolver::iterator end; ep_iter != end; ep_iter++)
            {
                if (ep_iter->endpoint().address().is_v4())
                {
                    dst_ip = ep_iter->endpoint().address().to_string();
                    dst_port = ep_iter->endpoint().port();
                    break;
                }
            }
        }
        else
        {
            cerr << "[resolve error]: " << ec.message() << endl;
            exit(1);
        }
    }
    //firewall check
    if (!firewall(request_))
    {
        reply_[0] = 0;
        reply_[1] = 91;
        cli_socket->send(boost::asio::buffer(reply_, 8));
    }
    else
    {
        reply_[0] = 0;
        reply_[1] = 90;
    }
    cout << "<S_IP>: " << cli_socket->remote_endpoint().address().to_string() << endl;
    cout << "<S_PORT>: " << cli_socket->remote_endpoint().port() << endl;
    cout << "<D_IP>: " << dst_ip << endl;
    cout << "<D_PORT>: " << dst_port << endl;
    cout << "<Commmand>: " << ((cd == 1) ? "Connect" : "Bind") << endl;
    cout << "<Reply>: " << ((reply_[1] == 91) ? "Reject" : "Accept") << "\n"
         << endl;
    if (reply_[1] == 91)
        exit(0);
    //Check connect or bind operation
    auto dst_socket = std::make_shared<tcp::socket>(io_context);
    if (cd == 1)
    {
        //connect
        tcp::endpoint ep(boost::asio::ip::address::from_string(dst_ip), dst_port);
        boost::system::error_code ec;
        dst_socket->connect(ep, ec);
        if (!ec)
            cli_socket->send(boost::asio::buffer(reply_, 8));
        else
        {
            cerr << "[connect error]: " << ec.message() << endl;
            exit(1);
        }
    }
    else if (cd == 2)
    {
        //bind
        boost::system::error_code ec;
        tcp::endpoint ep(tcp::v4(), INADDR_ANY);
        tcp::acceptor acceptor_(io_context, ep);

        reply_[2] = ep.port() / 256;
        reply_[3] = ep.port() % 256;
        reply_[4] = reply_[5] = reply_[6] = reply_[7] = 0;

        cli_socket->send(boost::asio::buffer(reply_, 8));
        acceptor_.accept(*dst_socket, ec);
        //check accept ip with request dst_ip
        cli_socket->send(boost::asio::buffer(reply_, 8));
    }
    //start relay session
    auto relay_1 = std::make_shared<session>(cli_socket, dst_socket);
    auto relay_2 = std::make_shared<session>(dst_socket, cli_socket);
    relay_1->start();
    relay_2->start();
    io_context.run();
}
class server
{
public:
    server(short port)
        : acceptor_(io_context, tcp::endpoint(tcp::v4(), port))
    {
        do_accept();
    }

private:
    void do_accept()
    {
        while (true)
        {
            auto socket_ = std::make_shared<tcp::socket>(io_context);
            acceptor_.accept(*socket_);
            io_context.notify_fork(boost::asio::execution_context::fork_prepare);
            if (fork() == 0)
            {
                io_context.notify_fork(boost::asio::execution_context::fork_child);
                socks_protocol(socket_);
                cout << "close connection\n";
                exit(0);
            }
            else
            {
                io_context.notify_fork(boost::asio::execution_context::fork_parent);
                socket_->close();
            }
        }
    }
    tcp::acceptor acceptor_;
};

int main(int argc, char *argv[])
{
    try
    {
        if (argc != 2)
        {
            std::cerr << "Usage: socks_server <port>\n";
            return 1;
        }
        server s(std::atoi(argv[1]));
    }
    catch (std::exception &e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}
