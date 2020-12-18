#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <utility>
#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>
#include <vector>
#include <array>

#define GRANTED 90
#define REJECT 91

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
std::array<u_char, max_length> data_;
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
	std::array<unsigned char, max_length> relay_data;

	void do_read()
	{
		auto self(shared_from_this());
		read_sock_->async_read_some(boost::asio::buffer(relay_data, max_length),
									[this, self](boost::system::error_code ec, std::size_t length) {
										if (!ec)
										{
											do_write(length);
										}
									});
	}

	void do_write(std::size_t length)
	{
		auto self(shared_from_this());
		send_sock_->async_send(boost::asio::buffer(relay_data, length),
							   [this, self](boost::system::error_code ec, std::size_t /*length*/) {
								   if (!ec)
								   {
									   do_read();
								   }
							   });
	}
};

bool firewall(u_char request[])
{
	std::ifstream conf("socks_conf");
	string rule, mode, addr;
	u_char addr_seg[4];

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
				addr_seg[i] = (u_char)std::stoul(addr.substr(0, pos));
				addr.erase(0, pos + 1);
			}
			else
				addr_seg[i] = (u_char)std::stoul(addr.substr(0, pos));
		}
		if (mode == "c" && request[1] == 1 || mode == "b" && request[1] == 2)
		{
			bool same_addr = true;
			for (int i = 0; i < 4; i++)
				if (addr_seg[i] != '*' && (addr_seg[i] != request[i + 4]))
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
	u_char request_[max_length];
	u_char reply_[8];

	std::size_t leng = cli_socket->read_some(boost::asio::buffer(request_));
	if(leng == -1){
		cout << "read error\n";
		exit(1);
	}
	u_char vn = request_[0];
	u_char cd = request_[1];
	u_short dst_port = request_[2] << 8 | request_[3];
	string dst_ip = std::to_string(request_[4]) + "." + std::to_string(request_[5]) + "." + std::to_string(request_[6]) + "." + std::to_string(request_[7]);
	string usr_id = (char *)(request_ + 8);

	cout << "usr_id: " << usr_id << endl;
	cout << "usr_id length: " << usr_id.length() <<endl;

	if (vn != 4 || cd != 1 || cd != 2)
	{
		cerr << "bad socks request";
		exit(0);
	}
	//socks4A
	if (request_[4] == 0 && request_[5] == 0 && request_[6] == 0 && request_[7] != 0)
	{
		string domain_name = (char *)request_ + 8 + usr_id.length() + 1;
		tcp::resolver resolver_(io_context);
		boost::system::error_code ec;
		tcp::resolver::iterator eps = resolver_.resolve(domain_name, std::to_string(dst_port), ec);
		if (!ec)
			dst_ip = eps->endpoint().address().to_string();
		else
		{
			cerr << "[error]: " << ec.message() << endl;
			exit(1);
		}
	}
	//firewall check
	if (!firewall(request_))
	{
		reply_[0] = 0;
		reply_[1] = REJECT;
		cli_socket->send(boost::asio::buffer(reply_, 8));
	}
	else{
		reply_[0] = 0;
		reply_[1] = GRANTED;
	}
	cout << "<S_IP>: " << cli_socket->remote_endpoint().address().to_string() << endl;
	cout << "<S_PORT>: " << cli_socket->remote_endpoint().port() << endl;
	cout << "<D_IP>: " << dst_ip << endl;
	cout << "<D_PORT>: " << dst_port << endl;
	cout << "<Commmand>: " << cd << endl;
	cout << "<Reply>: ";
	if (reply_[1] == REJECT)
	{
		cout << "Reject" << endl;
		exit(0);
	}
	else
		cout << "Accept" << endl;

	//Check connect or bind operation
	auto dst_socket = std::make_shared<tcp::socket>(io_context);
	if (cd == 1)
	{
		//connect
		boost::asio::ip::address addr;
		addr.from_string(dst_ip);
		tcp::endpoint ep(addr, dst_port);
		boost::system::error_code ec;
		dst_socket->connect(ep, ec);
		if (!ec)
			cli_socket->send(boost::asio::buffer(reply_, 8));
		else
		{
			cerr << "[error]: " << ec.message() << endl;
			exit(1);
		}
	}
	else if (cd == 2)
	{
		//bind
		boost::system::error_code ec;
		tcp::endpoint ep(tcp::v4(), 9000);
		tcp::acceptor acceptor_(io_context, ep);

		reply_[2] = ep.port() / 256;
		reply_[3] = ep.port() % 256;
		reply_[4] = 0;
		reply_[5] = 0;
		reply_[6] = 0;
		reply_[7] = 0;

		cli_socket->send(boost::asio::buffer(reply_, 8));
		acceptor_.accept(*dst_socket, ec);
		//check accept ip with request dst_ip
		
		cli_socket->send(boost::asio::buffer(reply_, 8));
	}
	//start relay session
	auto relay_1 = std::make_shared<session> (cli_socket, dst_socket);
	auto relay_2 = std::make_shared<session> (dst_socket, cli_socket);
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
		auto socket_ = std::make_shared<tcp::socket>(io_context);
		while (true)
		{
			acceptor_.accept(*socket_);
			io_context.notify_fork(boost::asio::execution_context::fork_prepare);
			if (fork() == 0)
			{
				io_context.notify_fork(boost::asio::execution_context::fork_child);
				socks_protocol(socket_);
				exit(0);
			}
			else
			{
				io_context.notify_fork(boost::asio::execution_context::fork_parent);
				acceptor_.accept(*socket_);
			}
		}
	}
	// enum{ max_length = 1024};
	// std::array<char, max_length> data_;
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
