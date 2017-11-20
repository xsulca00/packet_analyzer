GCC=g++
CFLAGS=-std=c++17 -Wall -Wextra -pedantic 

all: main.o arguments.o layer2.o layer3.o layer4.o
	$(GCC) $(CFLAGS) -o isashark main.o arguments.o layer2.o layer3.o layer4.o -lpcap

main.o: main.cpp
	$(GCC) $(CFLAGS) -c main.cpp

arguments.o: arguments.cpp
	$(GCC) $(CFLAGS) -c arguments.cpp

layer2.o: layer2.cpp
	$(GCC) $(CFLAGS) -c layer2.cpp

layer3.o: layer3.cpp
	$(GCC) $(CFLAGS) -c layer3.cpp

layer4.o: layer4.cpp
	$(GCC) $(CFLAGS) -c layer4.cpp

clean:
	rm -rf *.o

