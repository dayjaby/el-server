#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>
#include <array>
#include <boost/asio.hpp>

#include "client_serv.h"

using boost::asio::ip::tcp;

void push16(std::shared_ptr<std::vector<char> > msg, uint16_t value) {
    msg->push_back(value & 0xFF);
    msg->push_back((value >> 8) & 0xFF);
}

unsigned short read16(uint8_t* data) {
    return (data[0] << 8) + data[1];
}

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
    virtual void process_incoming_message(uint8_t command, std::size_t length, uint8_t* data) {
        switch (command) {
        case RAW_TEXT:
            break;
        case LOG_IN: {
                std::string username;
                std::string password;
                send_log_in_ok();
                send_change_map("maps/map2.elm.gz");
                send_you_are(0xFF13);
                send_add_new_enhanced_actor(0xFF13,
                    110, // x
                    110, // y
                    0, // rot
                    actor_types_type::draegoni_male,
                    SKIN_WHITE, // skin
                    HAIR_DARK_RED, // hair
                    SHIRT_BLACK, // shirt
                    PANTS_BLACK, // pants
                    BOOTS_BLACK, // boots
                    HEAD_1, // head
                    SHIELD_NONE, // shield
                    WEAPON_NONE, // weapon
                    CAPE_NONE, // cape
                    HELMET_NONE, // helmet
                    NECK_NONE, // neck
                    1000, // max health
                    500, // current health
                    1, // actor color
                    "David", "\0"
                );
                send_add_actor(0xF012, 109, 110, 0, 11, frame_idle, 100, 85, 1, "Goblin", 2);
            }
            break;
        case SEND_VERSION:
            handle_send_version(
                (uint8_t)data[0], (uint8_t)data[2],
                data[4], data[5], data[6], data[7],
                (uint8_t*)(&data[8]),
                read16(&data[12])
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
        std::cout << "version: " << version_first_digit << "." << version_second_digit << std::endl;
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

    void send_log_in_ok() {
        auto msg = std::make_shared<std::vector<char> >(3);
        msg->at(0) = LOG_IN_OK;
        do_write(msg);
    }

    void send_change_map(std::string map) {
        auto msg = std::make_shared<std::vector<char> >(3);
        msg->at(0) = CHANGE_MAP;
        std::copy(map.begin(), map.end(), std::back_inserter(*msg));
        msg->push_back(0);
        do_write(msg);
    }

    void send_you_are(uint16_t actor_id) {
        auto msg = std::make_shared<std::vector<char> >(3);
        msg->at(0) = YOU_ARE;
        push16(msg, actor_id);
        do_write(msg);
    }

    void send_add_actor(uint16_t actor_id, uint16_t x, uint16_t y, uint16_t z_rot, uint8_t actor_type, uint8_t frame, uint16_t max_health, uint16_t current_health, uint8_t actor_name_color, std::string name, float scale) {
        auto msg = std::make_shared<std::vector<char> >(3);
        msg->at(0) = ADD_NEW_ACTOR;
        push16(msg, actor_id);
        push16(msg, x);
        push16(msg, y);
        push16(msg, 0); // buffs, also encoded into x,y
        push16(msg, z_rot);
        msg->push_back(actor_type);
        msg->push_back(frame); // frame
        push16(msg, max_health);
        push16(msg, current_health);
        msg->push_back(actor_name_color);
        std::copy(name.begin(), name.end(), std::back_inserter(*msg));
        msg->push_back(0);

        //push16(msg, scale * 0x4000);
        do_write(msg);
    }

    void send_add_new_enhanced_actor(uint16_t actor_id, uint16_t x, uint16_t y, uint16_t z_rot, uint8_t actor_type, uint8_t skin, uint8_t hair, uint8_t shirt, uint8_t pants, uint8_t boots, uint8_t head, uint8_t shield, uint8_t weapon, uint8_t cape, uint8_t helmet, uint8_t neck, uint16_t max_health, uint16_t current_health, uint8_t actor_name_color, std::string name, std::string guild) {
        auto msg = std::make_shared<std::vector<char> >(3);
        msg->at(0) = ADD_NEW_ENHANCED_ACTOR;
        push16(msg, actor_id);
        push16(msg, x);
        push16(msg, y);
        push16(msg, 0); // buffs, also encoded into x,y
        push16(msg, z_rot);
        msg->push_back(actor_type);
        msg->push_back(0); // unused
        msg->push_back(skin);
        msg->push_back(hair);
        msg->push_back(shirt);
        msg->push_back(pants);
        msg->push_back(boots);
        msg->push_back(head);
        msg->push_back(shield);
        msg->push_back(weapon);
        msg->push_back(cape);
        msg->push_back(helmet);
        msg->push_back(neck);
        push16(msg, max_health);
        push16(msg, current_health);
        msg->push_back(actor_name_color);
        std::copy(name.begin(), name.end(), std::back_inserter(*msg));
        msg->push_back(0);
        std::copy(guild.begin(), guild.end(), std::back_inserter(*msg));
        msg->push_back(0);
        do_write(msg);
    }

private:
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
                                    process_incoming_message(read_data[0], length, read_data+3);

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
