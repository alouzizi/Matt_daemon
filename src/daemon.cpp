#include "../include/Tintin_reporter.hpp"

bool Tintin_reporter::daemonize() {
    pid_t pid = fork();
    
    if (pid < 0) {
        return false;
    }
    
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }
    
    if (setsid() < 0) {
        return false;
    }
    
    signal(SIGHUP, SIG_IGN);
    
    pid = fork();
    
    if (pid < 0) {
        return false;
    }
    
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }
    
    umask(0);
    
    if (chdir("/") < 0) {
        return false;
    }
    
    for (int fd = sysconf(_SC_OPEN_MAX); fd >= 0; fd--) {
        close(fd);
    }
    
    int null_fd = open("/dev/null", O_RDWR);
    if (null_fd >= 0) {
        dup2(null_fd, STDIN_FILENO);
        dup2(null_fd, STDOUT_FILENO);
        dup2(null_fd, STDERR_FILENO);
        
        if (null_fd > STDERR_FILENO) {
            close(null_fd);
        }
    }
    
    return true;
}

bool Tintin_reporter::createLockFile() {
    lock_fd = open(Config::LOCK_FILE, O_CREAT | O_RDWR, 0640);
    
    if (lock_fd < 0) {
        logError("Failed to create lock file: " + std::string(Config::LOCK_FILE) + " - " + std::string(strerror(errno)));
        return false;
    }
    

    struct flock fl;
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
    

    if (fcntl(lock_fd, F_SETLK, &fl) < 0) {
        logError("Failed to lock file (another instance may be running): " + std::string(strerror(errno)));
        close(lock_fd);
        return false;
    }
    
    if (ftruncate(lock_fd, 0) < 0) {
        logError("Failed to truncate lock file: " + std::string(strerror(errno)));
        close(lock_fd);
        return false;
    }
    
    std::string pid_str = std::to_string(getpid()) + "\n";
    if (write(lock_fd, pid_str.c_str(), pid_str.length()) < 0) {
        logError("Failed to write PID to lock file: " + std::string(strerror(errno)));
        close(lock_fd);
        return false;
    }
    
    fsync(lock_fd);
    
    log("Lock file created");
    return true;
}

void Tintin_reporter::setupSignalHandlers() {
    signal(SIGTERM, signalHandler);
    signal(SIGINT, signalHandler);
    signal(SIGQUIT, signalHandler);
    signal(SIGPIPE, SIG_IGN);
}

bool Tintin_reporter::checkExistingInstance() {
    int test_fd = open(Config::LOCK_FILE, O_RDWR);
    
    if (test_fd < 0) {
        return true;
    }
    
    struct flock fl;
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    
    if (fcntl(test_fd, F_SETLK, &fl) < 0) {
        std::cerr << "Error: Cannot create/open lock file " << Config::LOCK_FILE << std::endl;
        std::cerr << "Another instance of MattDaemon is already running." << std::endl;
        std::cerr << "Unable to start daemon - lock file acquisition failed." << std::endl;
        close(test_fd);
        return false;
    } else {
        close(test_fd);
        unlink(Config::LOCK_FILE);
        return true;
    }
}

void Tintin_reporter::signalHandler(int sig) {
    if (instance) {
        switch (sig) {
            case SIGTERM:
                instance->log("Received SIGTERM (signal 15) - terminating daemon");
                instance->shutdown();
                break;
            case SIGINT:
                instance->log("Received SIGINT (signal 2) - terminating daemon");
                instance->shutdown();
                break;
            case SIGQUIT:
                instance->log("Received SIGQUIT (signal 3) - terminating daemon");
                instance->shutdown();
                break;
            default:
                instance->log("Received signal " + std::to_string(sig) + " - no handler defined");
                break;
        }
    }
}


void Tintin_reporter::shutdown() {
    running = false;
    log("Initiating daemon shutdown...");
}