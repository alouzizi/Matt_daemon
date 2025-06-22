#ifndef BEN_AFK_HPP
#define BEN_AFK_HPP

#include "Config.hpp"
#include <string>
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

class Ben_AFK {
private:
    int socket_fd;
    bool connected;
    
    std::string receiveMessage();
    bool handleAuthentication();
    
public:
    Ben_AFK();
    
    Ben_AFK(const Ben_AFK& other) = delete;
    
    Ben_AFK& operator=(const Ben_AFK& other) = delete;
    
    ~Ben_AFK();
    
    bool connect();
    void disconnect();
    bool sendMessage(const std::string& message);
};

#endif
