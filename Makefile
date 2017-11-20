
LAYER3 = layer3/ip.cpp
LAYER4 = layer4/dissection.cpp layer4/tcp.cpp

all:
	g++ -std=c++17 -g -Wall -Wextra -pedantic -o isashark main.cpp arguments.cpp layer2.cpp $(LAYER3) $(LAYER4) -lpcap
