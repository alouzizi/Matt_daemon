# Matt_daemon

A modern C++ daemon implementation featuring the `Tintin_reporter` class that runs as a background service and accepts network connections.

## Features

### Core Features

- **Modern C++17**: Uses modern C++ features and best practices
- **Daemon Process**: Properly daemonizes and runs in the background
- **Signal Handling**: Graceful shutdown on SIGTERM/SIGINT
- **Lock File Management**: Prevents multiple instances from running
- **Network Server**: Listens on port 4242 for client connections with select()-based I/O multiplexing
- **Comprehensive Logging**: Logs to both syslog and file

### Bonus Features

- **Message Encryption**: XOR-based encryption for secure client-server communication
- **Authentication**: Optional password-based authentication for client connections
- **Client Application**: Includes a persistent connection test client (`Ben_AFK`) for communication
- **Utility Commands**: Status and uptime commands to monitor daemon health and statistics
- **Configurable Client Limit**: Support for more than 3 simultaneous client connections using the `-c` flag

## Building

**Important**: If using the Vagrant development environment, make sure to build inside the VM:

```bash
# On host machine (macOS/Windows) - for development only
make

# In Vagrant VM - for running the daemon
vagrant ssh
cd /home/vagrant/matt_daemon
make
```

This will build both `MattDaemon` (the daemon) and `Ben_AFK` (the test client).

**Note**: Binaries compiled on the host machine (macOS/Windows) won't run in the Linux VM. Always compile inside the target environment.

## Usage

### Running the Daemon

**In Vagrant VM:**
```bash
vagrant ssh
cd /home/vagrant/matt_daemon
sudo ./MattDaemon
```

**On native Linux:**
```bash
sudo ./MattDaemon
```

The daemon will:
1. Check for existing instances (via lock file)
2. Daemonize itself (fork and detach from terminal)
3. Start listening on port 4242
4. Log activity to `/var/log/matt_daemon/matt_daemon.log` and syslog

### Using the Client

In another terminal, run the client to communicate with the daemon:

```bash
./Ben_AFK
```

The client maintains a persistent connection to the daemon and handles authentication automatically if enabled. You can send multiple commands through the same connection.

**Interactive Usage:**
```bash
$ ./Ben_AFK
MattDaemon Client
Available commands: help, status, uptime, exit, quit
Connecting to server...
Enter password: [if authentication is enabled]
Authentication successful
Server: Welcome to MattDaemon
Available commands:
  help     - Show this help message
  status   - Show daemon status
  uptime   - Show daemon uptime
  exit     - Exit client
  quit     - Shutdown the daemon
Connected! Enter messages to send to MattDaemon:
help
Available commands:
  help     - Show this help message
  status   - Show daemon status
  uptime   - Show daemon uptime
  exit     - Exit client (disconnect from daemon)
  quit     - Shutdown the daemon

status
MattDaemon Status:
Status: Running
PID: 1234
Port: 4242
Connections: 1/3

uptime
MattDaemon Uptime:
Uptime: 2h 15m 30s

quit
Goodbye from MattDaemon
Daemon shutdown command sent. Exiting client.
```

**Available Commands:**
- `help` - Display available commands
- `status` - Show daemon status information
- `uptime` - Show daemon uptime
- `exit` - Exit client (disconnect from daemon)
- `quit` - Gracefully shutdown the daemon

### Checking Daemon Status

You can check if the daemon is running:

```bash
# Check if process is running
ps aux | grep MattDaemon

# Check the log file
sudo tail -f /var/log/matt_daemon/matt_daemon.log

```

### Stopping the Daemon

The daemon can be stopped in several ways:

1. Send `quit` command via the client
2. Send SIGTERM signal: `sudo pkill MattDaemon`
3. Send SIGINT signal: `sudo killall MattDaemon`

## Architecture

### Tintin_reporter Class

The main daemon class implements the singleton pattern and includes:

- **Initialization**: Sets up logging, lock file, daemonization, and server socket
- **Main Loop**: Uses `select()` for non-blocking I/O to handle multiple client connections efficiently
- **Connection Management**: Tracks and manages up to 3 concurrent client connections
- **Signal Handling**: Proper cleanup on termination signals
- **Network Handling**: TCP server that processes commands and maintains persistent connections
- **Authentication**: Optional password-based client authentication
- **Logging**: Dual logging to file and syslog

### Configuration

The daemon uses the following default configuration (see `include/Config.hpp`):

- **Port**: 4242
- **Max Connections**: 3 concurrent clients
- **Lock File**: `/var/lock/matt_daemon.lock`
- **Log File**: `/var/log/matt_daemon/matt_daemon.log`
- **Working Directory**: `/` (root)
- **Encryption**: Enabled (XOR cipher with configurable key)
- **Authentication**: Enabled (default password: "secure123")
- **I/O Model**: select()-based non-blocking I/O

### Security Features

- **Message Encryption**: All communication between client and daemon is encrypted using XOR cipher
- **Authentication**: Optional password-based authentication (configurable in Config.hpp)
- **Connection Limits**: Maximum of 3 concurrent connections to prevent resource exhaustion
- **Configurable Security**: Encryption and authentication can be disabled via configuration
- **Secure Key Management**: Encryption key and password hash can be changed in Config.hpp
- **Transparent Operation**: Encryption/decryption and authentication are automatic and transparent to users

## Development

### Clean Build

```bash
make fclean
make
```

### Testing

1. Build the project: `make`
2. Run the daemon as root: `sudo ./MattDaemon`
3. In another terminal, run the client: `./Ben_AFK`
4. If authentication is enabled, enter the password when prompted (default: "secure123")
5. Send test commands (help, status, uptime) and verify responses
6. Test multiple concurrent clients (up to 3 connections)
7. Send `quit` to cleanly shut down the daemon

## Security Considerations

- The daemon runs as root to access system directories and bind to privileged ports
- Lock file prevents multiple instances and potential conflicts
- Connection limit (3 clients) prevents resource exhaustion attacks
- Optional authentication provides access control
- Proper signal handling ensures clean shutdown and resource cleanup
- select()-based I/O eliminates threading-related security concerns
- Network interface is configurable (default: all interfaces on port 4242)

## Modern C++ Features Used

- **C++17 Standard**: Modern language features and best practices
- **RAII**: Automatic resource management for sockets, files, and connections
- **STL Containers**: Vector for managing active connections efficiently
- **Atomic Operations**: Thread-safe flag handling for clean shutdown
- **Chrono Library**: Modern time handling for uptime calculations
- **Exception Safety**: Proper error handling and resource cleanup
- **No Raw Pointers**: Safe memory management without manual allocation
- **Namespace Organization**: Clean separation of configuration and utilities
