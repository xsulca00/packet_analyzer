
all:
	g++ -std=c++14 -Wall -Wextra -pedantic -o isashark main.cpp arguments.cpp -lpcap
