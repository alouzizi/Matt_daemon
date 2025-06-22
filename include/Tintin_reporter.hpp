#ifndef TINTIN_REPORTER_HPP
#define TINTIN_REPORTER_HPP

#include <string>
#include <memory>
#include <fstream>
#include <iostream>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <fcntl.h>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <atomic>
#include <cerrno>
#include <vector>
#include "Config.hpp"

class Tintin_reporter {
private:
    static std::atomic<bool> running;
    static Tintin_reporter* instance;

    int lock_fd;
    std::ofstream log_file;
    int server_socket;
    std::vector<int> active_connections;
    std::chrono::system_clock::time_point start_time;
    
public:
    Tintin_reporter();
    
    Tintin_reporter(const Tintin_reporter&) = delete;
    
    Tintin_reporter& operator=(const Tintin_reporter&) = delete;
    
    ~Tintin_reporter();
    
    static Tintin_reporter& getInstance();
    
    bool initialize();
    void run();
    void shutdown();
    
    static void signalHandler(int sig);
    
    bool daemonize();
    bool checkExistingInstance();
    bool createLockFile();
    void setupSignalHandlers();
    void setupLogging();
    
    bool setupServer();
    void handleClient(int client_socket);
    void processCommand(const std::string& command, int client_socket);
    bool authenticateClient(int client_socket);
    
    void log(const std::string& message);
    void logError(const std::string& message);
    std::string formatTimestamp(const std::chrono::system_clock::time_point& time_point);
    
    std::string getStatus();
    std::string getUptime();
    
    void cleanup();
};

#endif
