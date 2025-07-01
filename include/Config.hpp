#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <string>
#include <vector>

namespace Config {
    static constexpr const char* DAEMON_NAME = "MattDaemon";
    
    static constexpr const char* LOCK_FILE = "/var/lock/matt_daemon.lock";
    static constexpr const char* LOG_FILE = "/var/log/matt_daemon/matt_daemon.log";
    
    static constexpr int SERVER_PORT = 4242;
    static constexpr int DEFAULT_MAX_CONNECTIONS = 3;
    
    extern int MAX_CONNECTIONS;
    
    static constexpr size_t BUFFER_SIZE = 1024;
    
    static constexpr bool ENABLE_FILE_LOGGING = true;
    static constexpr bool ENABLE_SYSLOG = true;
    
    namespace Commands {
        static const std::string QUIT = "quit";
        static const std::string EXIT = "exit";
        static const std::string STATUS = "status";
        static const std::string HELP = "help";
        static const std::string UPTIME = "uptime";
    }

    namespace Responses {
        static const std::string WELCOME = R"(Welcome to MattDaemon
Available commands:
  help     - Show this help message
  status   - Show daemon status
  uptime   - Show daemon uptime
  exit     - Exit client
  quit     - Shutdown the daemon)";
        static const std::string GOODBYE = "Goodbye from MattDaemon";
        static const std::string CLIENT_EXIT = "Client disconnected";
        static const std::string HELP_TEXT = R"(Available commands:
  help     - Show this help message
  status   - Show daemon status
  uptime   - Show daemon uptime
  exit     - Exit client (disconnect from daemon)
  quit     - Shutdown the daemon
)";
    }

    static constexpr const char* ENCRYPTION_KEY = "MattDaemon2025SecretKey";
    static constexpr bool ENABLE_ENCRYPTION =true;
    
    static constexpr bool ENABLE_AUTHENTICATION = true;
    // Password: "secure123" (encrypted with XOR)
    static constexpr const char* PASSWORD_HASH = "3E0417013604545F5C";
    static const std::string AUTH_PROMPT = "Enter password: ";
    static const std::string AUTH_SUCCESS = "Authentication successful";
    static const std::string AUTH_FAILED = "Authentication failed";
    
    namespace Crypto {
        inline std::string xorEncrypt(const std::string& data, const std::string& key) {
            std::string result = data;
            for (size_t i = 0; i < data.length(); ++i) {
                result[i] = data[i] ^ key[i % key.length()];
            }
            return result;
        }
        inline std::string xorDecrypt(const std::string& data, const std::string& key) {
            return xorEncrypt(data, key);
        }
        
        inline std::string toHex(const std::string& data) {
            std::string hex;
            char buffer[3];
            for (unsigned char c : data) {
                sprintf(buffer, "%02X", c);
                hex += buffer;
            }
            return hex;
        }

        inline std::string fromHex(const std::string& hex) {
            std::string data;
            data.reserve(hex.length() / 2);
            for (size_t i = 0; i < hex.length(); i += 2) {
                std::string byteString = hex.substr(i, 2);
                char byte = static_cast<char>(std::stoi(byteString, nullptr, 16));
                data += byte;
            }
            return data;
        }
        
        inline std::string encryptMessage(const std::string& message) {
            if (!ENABLE_ENCRYPTION) {
                return message;
            }
            std::string encrypted = xorEncrypt(message, ENCRYPTION_KEY);
            return toHex(encrypted);
        }
        
        inline std::string decryptMessage(const std::string& encryptedHex) {
            if (!ENABLE_ENCRYPTION) {
                return encryptedHex;
            }
            try {
                if (encryptedHex.empty() || encryptedHex.length() % 2 != 0) {
                    return "";
                }
                
                for (char c : encryptedHex) {
                    if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) {
                        return "";
                    }
                }
                
                std::string encrypted = fromHex(encryptedHex);
                std::string decrypted = xorDecrypt(encrypted, ENCRYPTION_KEY);
                
                for (char c : decrypted) {
                    if (c != '\n' && c != '\r' && c != '\t' && (c < 32 || c > 126)) {
                        return "";
                    }
                }
                
                return decrypted;
            } catch (...) {
                return "";
            }
        }
        
        inline bool verifyPassword(const std::string& password) {
            if (!ENABLE_AUTHENTICATION) {
                return true;
            }
            std::string encrypted_password = toHex(xorEncrypt(password, ENCRYPTION_KEY));
            return encrypted_password == PASSWORD_HASH;
        }
    }
}

#endif
