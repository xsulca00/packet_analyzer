
LAYER2 = layer2/ethernet.cpp layer2/vlan.cpp
LAYER3 = layer3/ip.cpp
LAYER4 = layer4/dissection.cpp layer4/tcp.cpp

all:
	g++ -std=c++17 -g -Wall -Wextra -pedantic -o isashark main.cpp arguments.cpp $(LAYER2) $(LAYER3) $(LAYER4) -lpcap
