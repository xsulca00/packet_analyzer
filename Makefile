
all:
	g++ -std=c++17 -g -Wall -Wextra -pedantic -o isashark main.cpp arguments.cpp layer2.cpp layer3.cpp layer4.cpp -lpcap
