#include "../include/Tintin_reporter.hpp"
#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <getopt.h>

namespace Config {
    int MAX_CONNECTIONS = DEFAULT_MAX_CONNECTIONS;
}

void printUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -c, --connections <num>    Maximum number of connections (default: " 
              << Config::DEFAULT_MAX_CONNECTIONS << ")" << std::endl;
    std::cout << "  -h, --help                 Show this help message" << std::endl;
    std::cout << std::endl;
    std::cout << "Note: This daemon must be run as root." << std::endl;
}

int main(int argc, char* argv[]) {
    int opt;
    static struct option long_options[] = {
        {"connections", required_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "c:h", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'c': {
                int connections = std::atoi(optarg);
                if (connections <= 0 || connections > 100) {
                    std::cerr << "Error: Invalid number of connections. Must be between 1 and 100." << std::endl;
                    return EXIT_FAILURE;
                }
                Config::MAX_CONNECTIONS = connections;
                break;
            }
            case 'h':
                printUsage(argv[0]);
                return EXIT_SUCCESS;
            case '?':
                std::cerr << "Error: Invalid option. Use -h or --help for usage information." << std::endl;
                return EXIT_FAILURE;
            default:
                printUsage(argv[0]);
                return EXIT_FAILURE;
        }
    }
    
    if (optind < argc) {
        std::cerr << "Error: Unexpected arguments provided." << std::endl;
        printUsage(argv[0]);
        return EXIT_FAILURE;
    }
    
    if (getuid() != 0) {
        std::cerr << "Error: MattDaemon must be run as root." << std::endl;
        std::cerr << "Please run with: sudo ./MattDaemon" << std::endl;
        return EXIT_FAILURE;
    }
    
    try {
        Tintin_reporter& daemon = Tintin_reporter::getInstance();
        
        if (!daemon.initialize()) {
            std::cerr << "Failed to initialize Matt_daemon" << std::endl;
            return EXIT_FAILURE;
        }
        
        daemon.run();
        
        return EXIT_SUCCESS;
    }
    catch (const std::exception& e) {
        std::cerr << "Exception in Matt_daemon: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    catch (...) {
        std::cerr << "Unknown exception in Matt_daemon" << std::endl;
        return EXIT_FAILURE;
    }
}
