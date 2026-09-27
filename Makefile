CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Iinclude

SRCS = src/main.cpp src/PermissionGraph.cpp src/Scanner.cpp
OBJS = $(SRCS:.cpp=.o)
EXEC = scan

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(EXEC) snapshot.csv outbreak_map.dot
