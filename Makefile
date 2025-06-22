CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Werror -pedantic -O2
TARGET = MattDaemon
CLIENT = Ben_AFK
SRCDIR = src
INCDIR = include

DAEMON_SOURCES = $(SRCDIR)/main.cpp $(SRCDIR)/Tintin_reporter.cpp
DAEMON_OBJECTS = $(DAEMON_SOURCES:.cpp=.o)

CLIENT_SOURCES = $(SRCDIR)/Ben_AFK.cpp
CLIENT_OBJECTS = $(CLIENT_SOURCES:.cpp=.o)

.PHONY: all clean fclean re

all: $(TARGET) $(CLIENT)

$(TARGET): $(DAEMON_OBJECTS)
	$(CXX) $(CXXFLAGS) -I$(INCDIR) $(DAEMON_OBJECTS) -o $(TARGET)

$(CLIENT): $(CLIENT_OBJECTS)
	$(CXX) $(CXXFLAGS) -I$(INCDIR) $(CLIENT_OBJECTS) -o $(CLIENT)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -I$(INCDIR) -c $< -o $@

clean:
	rm -f $(DAEMON_OBJECTS) $(CLIENT_OBJECTS)

fclean: clean
	rm -f $(TARGET) $(CLIENT)

re: fclean all
