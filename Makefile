
all:
	g++ -std=c++14 -g -Wall -Wextra -pedantic -o isashark main.cpp arguments.cpp -lpcap
