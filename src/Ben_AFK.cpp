#include "../include/Ben_AFK.hpp"

std::string Ben_AFK::receiveMessage() {
    if (!connected || socket_fd < 0) {
        return "";
    }
    
    char buffer[1024];
    ssize_t bytes_received = recv(socket_fd, buffer, sizeof(buffer) - 1, 0);
    
    if (bytes_received <= 0) {
        disconnect();
        return "";
    }
    
    buffer[bytes_received] = '\0';
    return Config::Crypto::decryptMessage(std::string(buffer));
}

Ben_AFK::Ben_AFK() : socket_fd(-1), connected(false) {}

Ben_AFK::~Ben_AFK() {
    disconnect();
}

bool Ben_AFK::connect() {
        if (connected) {
            return true;
        }
        
        socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (socket_fd < 0) {
            std::cerr << "Failed to create socket" << std::endl;
            return false;
        }
        
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(Config::SERVER_PORT);
        server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        
        if (::connect(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "Failed to connect to server" << std::endl;
            close(socket_fd);
            socket_fd = -1;
            return false;
        }
        
        connected = true;
        
        std::string initial_message = receiveMessage();
        if (!initial_message.empty()) {
            if (initial_message.find("ERROR:") != std::string::npos && 
                initial_message.find("Maximum number of connections") != std::string::npos) {
                std::cout << initial_message << std::endl;
                disconnect();
                return false;
            }
            
            if (initial_message.find("Enter password") != std::string::npos) {
                std::cout << initial_message << std::flush;
                
                std::string password;
                std::getline(std::cin, password);
                
                std::string encrypted_password = Config::Crypto::encryptMessage(password);
                if (send(socket_fd, encrypted_password.c_str(), encrypted_password.length(), 0) < 0) {
                    disconnect();
                    return false;
                }
                
                std::string auth_response = receiveMessage();
                if (!auth_response.empty()) {
                    std::cout << auth_response << std::endl;
                    if (auth_response.find("successful") == std::string::npos) {
                        disconnect();
                        return false;
                    }
                }
                
                std::string welcome = receiveMessage();
                if (!welcome.empty()) {
                    std::cout << welcome << std::endl;
                }
            } else {
                std::cout << initial_message << std::endl;
            }
        } else {
            if (!handleAuthentication()) {
                disconnect();
                return false;
            }
            
            std::string welcome = receiveMessage();
            if (!welcome.empty()) {
                std::cout << welcome << std::endl;
            }
        }
        
        return true;
    }
    
    void Ben_AFK::disconnect() {
        if (socket_fd >= 0) {
            close(socket_fd);
            socket_fd = -1;
        }
        connected = false;
    }
    
    bool Ben_AFK::sendMessage(const std::string& message) {
        if (!connected) {
            std::cerr << "Not connected to server" << std::endl;
            return false;
        }
        
        std::string encrypted_message = Config::Crypto::encryptMessage(message);
        
        if (send(socket_fd, encrypted_message.c_str(), encrypted_message.length(), 0) < 0) {
            std::cerr << "Failed to send message" << std::endl;
            disconnect();
            return false;
        }
        
        if (message == "quit" || message == "exit") {
            std::string response = receiveMessage();
            if (!response.empty()) {
                std::cout << response << std::endl;
            }
            disconnect();
            return false;
        }
        
        if (message == "help" || message == "status" || message == "uptime") {
            std::string response = receiveMessage();
            if (!response.empty()) {
                std::cout << response << std::endl;
            }
        }
        
        return true;
    }
    
    bool Ben_AFK::handleAuthentication() {
        std::string response = receiveMessage();
        if (response.empty() || response.find("Enter password") == std::string::npos) {
            return true;
        }
        
        std::cout << response << std::flush;
        
        std::string password;
        std::getline(std::cin, password);
        
        std::string encrypted_password = Config::Crypto::encryptMessage(password);
        if (send(socket_fd, encrypted_password.c_str(), encrypted_password.length(), 0) < 0) {
            return false;
        }
        
        std::string auth_response = receiveMessage();
        if (!auth_response.empty()) {
            std::cout << auth_response << std::endl;
            return auth_response.find("successful") != std::string::npos;
        }
        
        return false;
    }

int main() {
    Ben_AFK client;
    
    if (!client.connect()) {
        return 1;
    }
    
    std::string input;
    while (std::getline(std::cin, input)) {
        if (!input.empty() && !client.sendMessage(input)) {
            break;
        }
    }
    
    return 0;
}
