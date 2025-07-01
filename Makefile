CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Werror
TARGET = MattDaemon
CLIENT = Ben_AFK
SRCDIR = src
INCDIR = include
TINTIN_INC = $(INCDIR)/Tintin_reporter.hpp
BEN_AFK_INC = $(INCDIR)/Ben_AFK.hpp
CONFIG_INC = $(INCDIR)/Config.hpp

DAEMON_SOURCES = $(SRCDIR)/main.cpp $(SRCDIR)/Tintin_reporter.cpp $(SRCDIR)/daemon.cpp
DAEMON_OBJECTS = $(DAEMON_SOURCES:.cpp=.o)

CLIENT_SOURCES = $(SRCDIR)/Ben_AFK.cpp
CLIENT_OBJECTS = $(CLIENT_SOURCES:.cpp=.o)


all: $(TARGET) $(CLIENT)

$(TARGET): $(DAEMON_OBJECTS) $(TINTIN_INC) $(CONFIG_INC) 
	$(CXX) $(CXXFLAGS) -I$(INCDIR) $(DAEMON_OBJECTS) -o $(TARGET)

$(CLIENT): $(CLIENT_OBJECTS) $(BEN_AFK_INC) $(CONFIG_INC)
	$(CXX) $(CXXFLAGS) -I$(INCDIR) $(CLIENT_OBJECTS) -o $(CLIENT)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -I$(INCDIR) -c $< -o $@

clean:
	rm -f $(DAEMON_OBJECTS) $(CLIENT_OBJECTS)

fclean: clean
	rm -f $(TARGET) $(CLIENT)

kill:
	@sudo pkill $(TARGET) || true

run:
	@sudo ./$(TARGET)

re: fclean all

.PHONY: all clean fclean re kill run