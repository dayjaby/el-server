#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>
#include <array>
#include <boost/asio.hpp>

#include "client_serv.h"

using boost::asio::ip::tcp;

class session
    : public std::enable_shared_from_this<session>
{
public:
    session(tcp::socket&& socket) : 
        socket_(std::move(socket))
    {
    }

    void start()
    {
        do_read();
    }

protected:
    virtual void process_incoming_message(uint8_t* data, std::size_t length) {
        switch (data[0]) {
        case RAW_TEXT:
            break;
        case LOG_IN:
            break;
        case SEND_VERSION:
            handle_send_version(
                (uint8_t)data[1], (uint8_t)data[3],
                data[5], data[6], data[7], data[8],
                (uint8_t*)(data+9),
                (data[13] << 8) + data[4]
            );
            break;
        case SEND_OPENING_SCREEN:
            handle_send_opening_screen();
        }
    }

    virtual void handle_send_opening_screen() { 
        send_raw_text(0x01, "Hello on this private EL server 0x00");
        send_raw_text(0x01, "Hello on this private EL server 0x01");
        send_raw_text(0x01, "Hello on this private EL server 0x02");
    }

    virtual void handle_send_version(uint16_t version_first_digit, uint16_t version_second_digit, uint8_t client_version_major, uint8_t client_version_minor, uint8_t client_version_release, uint8_t client_version_patch, uint8_t host[4], uint16_t port) {
        if (version_first_digit < 9) {
            send_raw_text(0xFF, "Client too old. Please update!");
        }
    }

    void send_raw_text(uint8_t channel, std::string message) {
        auto msg = std::make_shared<std::vector<char> >(3);
        msg->at(0) = RAW_TEXT;
        msg->push_back(channel);
        std::copy(message.begin(), message.end(), std::back_inserter(*msg));
        msg->push_back(0);
        do_write(msg);
    }

private:
    void le16(uint8_t* buf, unsigned short word) {
    }

    void do_read()
    {
        auto self(shared_from_this());
        boost::asio::async_read(socket_, boost::asio::buffer(read_data, 3),
            [this, self](boost::system::error_code ec, std::size_t length)
            {
                if (!ec && length == 3)
                {
                    std::cout << (int)read_data[0] << ", " << (int)read_data[1] << ", " << (int)read_data[2] << std::endl;
                    short message_length = read_data[1] + (read_data[2] << 8);
                    if (message_length < max_length) {
                        boost::asio::async_read(socket_, boost::asio::buffer(read_data+3, message_length-1),
                            [this, self, message_length](boost::system::error_code ec, std::size_t length)
                            {
                                if (!ec)
                                {
                                    for (int i = 3; i < length+3; ++i) {
                                        std::cout << (int)read_data[i] << ", ";
                                    }
                                    std::cout << std::endl;
                                    process_incoming_message(read_data, length+3);

                                    // next read only after finishing processing the previous incoming message as we are re-using the buffer
                                    do_read();
                                }
                            }
                        );
                    }
                }
            }
        );
    }

    void do_write(std::shared_ptr<std::vector<char> > write_data)
    {
        unsigned short length = write_data->size() - 2;
        write_data->at(1) = length & 0xFF;
        write_data->at(2) = (length >> 8) & 0xFF;

        auto self(shared_from_this());
        std::cout << "Sending: ";
        for (int i = 0; i < length+2; ++i) {
            std::cout << (int)write_data->at(i) << ", ";
        }
        std::cout << std::endl;
        boost::asio::async_write(socket_, boost::asio::buffer(*write_data),
                                 [this, self, write_data](boost::system::error_code ec, std::size_t length)
        {
            if (!ec)
            {
                std::cout << "sent " << length << " bytes" << std::endl;
            }
        });
    }

    tcp::socket socket_;
    enum { max_length = 1024 };
    uint8_t read_data[max_length];
};

class server
{
public:
    server(boost::asio::io_context& io_context, short port) :
        acceptor_(io_context, tcp::endpoint(tcp::v4(), port))
    {
        do_accept(io_context);
    }

private:
    void do_accept(boost::asio::io_context& io_context)
    {
        acceptor_.async_accept(
            [this, &io_context](boost::system::error_code ec, tcp::socket socket)
        {
            if (!ec)
            {
                /*
                tcp::resolver resolver(io_context);
                try {
                    boost::asio::connect(proxy_, resolver.resolve("192.99.21.222", "2000"));
                }
                catch (std::exception& e)
                {
                    std::cerr << "Exception: " << e.what() << "\n";
                }
                connected = true;
                */
                std::make_shared<session>(std::move(socket))->start();
            }

            do_accept(io_context);
        });
    }

    tcp::acceptor acceptor_;
    bool connected;
};

int main(int argc, char* argv[])
{
    try
    {
        if (argc != 2)
        {
            std::cerr << "Usage: server <port>\n";
            return 1;
        }

        boost::asio::io_context io_context;

        server s(io_context, std::atoi(argv[1]));

        io_context.run();
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}
