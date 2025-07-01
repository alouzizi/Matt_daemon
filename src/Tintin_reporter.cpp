#include "../include/Tintin_reporter.hpp"
#include <sstream>
#include <netinet/in.h>
#include <algorithm>
#include <iomanip>

std::atomic<bool> Tintin_reporter::running{false};
Tintin_reporter* Tintin_reporter::instance = nullptr;

Tintin_reporter::Tintin_reporter() : lock_fd(-1), server_socket(-1) {
    instance = this;
    start_time = std::chrono::system_clock::now();
}

Tintin_reporter::~Tintin_reporter() {
    cleanup();
}

Tintin_reporter& Tintin_reporter::getInstance() {
    static Tintin_reporter instance;
    return instance;
}

bool Tintin_reporter::initialize() {
    if (!checkExistingInstance()) {
        return false;
    }
    
    if (!daemonize()) {
        std::cerr << "Failed to daemonize process" << std::endl;
        return false;
    }
    
    setupLogging();
    log("MattDaemon starting up...");
    log("Configuration: Max connections = " + std::to_string(Config::MAX_CONNECTIONS));
    
    if (!createLockFile()) {
        logError("Failed to create/open lock file - unable to start daemon");
        return false;
    }
    
    setupSignalHandlers();
    
    if (!setupServer()) {
        logError("Failed to setup server socket");
        return false;
    }
    
    log("MattDaemon initialized successfully");
    return true;
}

void Tintin_reporter::run() {
    running = true;
    log("MattDaemon is now running");
    
    fd_set read_fds, master_fds;
    struct timeval timeout;
    int max_fd = server_socket;
    
    FD_ZERO(&master_fds);
    FD_SET(server_socket, &master_fds);
    
    while (running) {
        read_fds = master_fds;
        
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int activity = select(max_fd + 1, &read_fds, nullptr, nullptr, &timeout);
        
        if (activity < 0 && errno != EINTR) {
            logError("Select error: " + std::string(strerror(errno)));
            break;
        }
        
        if (activity > 0) {
            if (FD_ISSET(server_socket, &read_fds)) {
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                
                int client_socket = accept(server_socket, 
                                         (struct sockaddr*)&client_addr, 
                                         &client_len);
                
                if (client_socket >= 0) {
                    if (active_connections.size() >= static_cast<size_t>(Config::MAX_CONNECTIONS)) {
                        log("Connection limit reached - client rejected");
                        
                        std::string error_msg = "ERROR: Maximum number of connections (" + 
                                              std::to_string(Config::MAX_CONNECTIONS) + 
                                              ") reached. Connection rejected.\n";
                        std::string encrypted_error = Config::Crypto::encryptMessage(error_msg);
                        send(client_socket, encrypted_error.c_str(), encrypted_error.length(), 0);
                        
                        usleep(100000);
                        
                        close(client_socket);
                    } else {
                        active_connections.push_back(client_socket);
                        FD_SET(client_socket, &master_fds);
                        
                        if (client_socket > max_fd) {
                            max_fd = client_socket;
                        }
                        
                        log("Client connected");
                        
                        if (!authenticateClient(client_socket)) {
                            active_connections.erase(
                                std::remove(active_connections.begin(), 
                                           active_connections.end(), client_socket),
                                active_connections.end()
                            );
                            FD_CLR(client_socket, &master_fds);
                            close(client_socket);
                        } else {
                            std::string welcome = Config::Responses::WELCOME + "\n";
                            std::string encrypted_welcome = Config::Crypto::encryptMessage(welcome);
                            send(client_socket, encrypted_welcome.c_str(), encrypted_welcome.length(), 0);
                        }
                    }
                }
            }
            
            for (auto it = active_connections.begin(); it != active_connections.end();) {
                int client_socket = *it;
                
                if (FD_ISSET(client_socket, &read_fds)) {
                    char buffer[Config::BUFFER_SIZE];
                    ssize_t bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
                    
                    if (bytes_received > 0) {
                        buffer[bytes_received] = '\0';
                        
                        std::string message(buffer);
                        if (!message.empty() && message.back() == '\n') {
                            message.pop_back();
                        }
                        
                        processCommand(message, client_socket);
                        
                        std::string decrypted_message = Config::Crypto::decryptMessage(message);
                        if (decrypted_message == Config::Commands::QUIT) {
                            ++it;
                            continue;
                        } else if (decrypted_message == Config::Commands::EXIT) {
                            log("Client disconnected");
                            FD_CLR(client_socket, &master_fds);
                            close(client_socket);
                            it = active_connections.erase(it);
                            continue;
                        }
                        
                        ++it;
                    } else {
                        log("Client disconnected");
                        FD_CLR(client_socket, &master_fds);
                        close(client_socket);
                        it = active_connections.erase(it);
                    }
                } else {
                    ++it;
                }
            }
        }
    }
    
    for (int client_socket : active_connections) {
        close(client_socket);
    }
    active_connections.clear();
    
    log("MattDaemon shutting down...");
}

bool Tintin_reporter::setupServer() {
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    
    if (server_socket < 0) {
        return false;
    }
    
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(server_socket);
        return false;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(Config::SERVER_PORT);
    
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(server_socket);
        return false;
    }
    
    if (listen(server_socket, Config::MAX_CONNECTIONS) < 0) {
        close(server_socket);
        return false;
    }
    
    log("Server started");
    return true;
}

void Tintin_reporter::processCommand(const std::string& command, int client_socket) {
    std::string response;
    
    std::string decrypted_command = Config::Crypto::decryptMessage(command);
    
    log("Received: " + decrypted_command);
    
    if (decrypted_command == Config::Commands::QUIT) {
        response = Config::Responses::GOODBYE;
        std::string encrypted_response = Config::Crypto::encryptMessage(response);
        send(client_socket, encrypted_response.c_str(), encrypted_response.length(), 0);
        log("Quit command received");
        shutdown();
    }
    else if (decrypted_command == Config::Commands::EXIT) {
        response = Config::Responses::CLIENT_EXIT;
        std::string encrypted_response = Config::Crypto::encryptMessage(response);
        send(client_socket, encrypted_response.c_str(), encrypted_response.length(), 0);
        log("Exit command received - client disconnecting");
    }
    else if (decrypted_command == Config::Commands::STATUS) {
        response = getStatus();
        std::string encrypted_response = Config::Crypto::encryptMessage(response);
        send(client_socket, encrypted_response.c_str(), encrypted_response.length(), 0);
    }
    else if (decrypted_command == Config::Commands::UPTIME) {
        response = getUptime();
        std::string encrypted_response = Config::Crypto::encryptMessage(response);
        send(client_socket, encrypted_response.c_str(), encrypted_response.length(), 0);
    }
    else if (decrypted_command == Config::Commands::HELP) {
        response = Config::Responses::HELP_TEXT;
        std::string encrypted_response = Config::Crypto::encryptMessage(response);
        send(client_socket, encrypted_response.c_str(), encrypted_response.length(), 0);
    }
}

bool Tintin_reporter::authenticateClient(int client_socket) {
    if (!Config::ENABLE_AUTHENTICATION) {
        return true;
    }
    
    char buffer[Config::BUFFER_SIZE];
    std::string prompt = Config::AUTH_PROMPT;
    std::string encrypted_prompt = Config::Crypto::encryptMessage(prompt);
    if (send(client_socket, encrypted_prompt.c_str(), encrypted_prompt.length(), 0) < 0) {
        logError("Failed to send authentication prompt");
        return false;
    }

    struct timeval timeout;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    ssize_t bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received <= 0) {
        logError("Failed to receive password or timeout occurred");
        return false;
    }
    buffer[bytes_received] = '\0';

    std::string password_input(buffer);
    std::string decrypted_password = Config::Crypto::decryptMessage(password_input);
    if (decrypted_password.empty()) {
        decrypted_password = password_input;
        logError("Password decryption failed, trying as plain text");
    }
    if (!decrypted_password.empty() && decrypted_password.back() == '\n') {
        decrypted_password.pop_back();
    }
    if (!decrypted_password.empty() && decrypted_password.back() == '\r') {
        decrypted_password.pop_back();
    }

    if (Config::Crypto::verifyPassword(decrypted_password)) {
        std::string success_msg = Config::AUTH_SUCCESS + "\n";
        std::string encrypted_success = Config::Crypto::encryptMessage(success_msg);
        if (send(client_socket, encrypted_success.c_str(), encrypted_success.length(), 0) < 0) {
            logError("Failed to send authentication success message");
            return false;
        }
        usleep(10000);
        log("Client authentication successful");
        return true;
    } else {
        std::string failure_msg = Config::AUTH_FAILED + "\n";
        std::string encrypted_failure = Config::Crypto::encryptMessage(failure_msg);
        send(client_socket, encrypted_failure.c_str(), encrypted_failure.length(), 0);
        usleep(10000);
				log("Client disconnected due to authentication failure");
        return false;
    }
}

std::string Tintin_reporter::formatTimestamp(const std::chrono::system_clock::time_point& time_point) {
    auto time_t = std::chrono::system_clock::to_time_t(time_point);
    auto tm = *std::localtime(&time_t);
    
    std::stringstream ss;
    ss << "[" 
       << std::setfill('0') << std::setw(2) << tm.tm_mday << "/"
       << std::setfill('0') << std::setw(2) << (tm.tm_mon + 1) << "/"
       << (tm.tm_year + 1900) << "-"
       << std::setfill('0') << std::setw(2) << tm.tm_hour << ":"
       << std::setfill('0') << std::setw(2) << tm.tm_min << ":"
       << std::setfill('0') << std::setw(2) << tm.tm_sec << "]";
       
    return ss.str();
}

void Tintin_reporter::log(const std::string& message) {
    auto now = std::chrono::system_clock::now();
    std::string timestamp = formatTimestamp(now);
    
    std::string log_message = timestamp + " " + message;
    
    syslog(LOG_INFO, "%s", log_message.c_str());
    
    if (log_file.is_open()) {
        log_file << log_message << std::endl;
        log_file.flush();
    }
}

void Tintin_reporter::logError(const std::string& message) {
    auto now = std::chrono::system_clock::now();
    std::string timestamp = formatTimestamp(now);
    
    std::string log_message = timestamp + " ERROR: " + message;
    
    syslog(LOG_ERR, "%s", log_message.c_str());
    
    if (log_file.is_open()) {
        log_file << log_message << std::endl;
        log_file.flush();
    }
}

void Tintin_reporter::cleanup() {
    if (server_socket >= 0) {
        close(server_socket);
        server_socket = -1;
    }
    
    if (lock_fd >= 0) {
        close(lock_fd);
        unlink(Config::LOCK_FILE);
        lock_fd = -1;
    }
    
    if (log_file.is_open()) {
        log_file.close();
    }
    
    if (Config::ENABLE_SYSLOG) {
        closelog();
    }
}

std::string Tintin_reporter::getStatus() {
    std::string status = "MattDaemon Status:\n";
    status += "Status: Running\n";
    status += "PID: " + std::to_string(getpid()) + "\n";
    status += "Port: " + std::to_string(Config::SERVER_PORT) + "\n";
    status += "Connections: " + std::to_string(active_connections.size()) + "/" + std::to_string(Config::MAX_CONNECTIONS) + "\n";
    
    return status;
}

std::string Tintin_reporter::getUptime() {
    auto now = std::chrono::system_clock::now();
    auto uptime_duration = now - start_time;
    
    auto hours = std::chrono::duration_cast<std::chrono::hours>(uptime_duration).count();
    auto minutes = std::chrono::duration_cast<std::chrono::minutes>(uptime_duration % std::chrono::hours(1)).count();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(uptime_duration % std::chrono::minutes(1)).count();
    
    std::string uptime = "MattDaemon Uptime:\n";
    uptime += "Uptime: " + std::to_string(hours) + "h " + std::to_string(minutes) + "m " + std::to_string(seconds) + "s\n";
    
    return uptime;
}


void Tintin_reporter::setupLogging() {
    if (Config::ENABLE_SYSLOG) {
        openlog(Config::DAEMON_NAME, LOG_PID | LOG_CONS, LOG_DAEMON);
    }
    
    if (Config::ENABLE_FILE_LOGGING) {
        const char* log_dir = "/var/log/matt_daemon";
        if (mkdir(log_dir, 0755) == -1 && errno != EEXIST) {
            syslog(LOG_WARNING, "Could not create log directory %s: %s", log_dir, strerror(errno));
        }
        
        log_file.open(Config::LOG_FILE, std::ios::app);
        if (!log_file.is_open()) {
            syslog(LOG_WARNING, "Could not open log file %s: %s", Config::LOG_FILE, strerror(errno));
            std::string fallback_log = "./matt_daemon.log";
            log_file.open(fallback_log, std::ios::app);
            if (log_file.is_open()) {
                syslog(LOG_INFO, "Using fallback log file: %s", fallback_log.c_str());
            }
        }
    }
}
