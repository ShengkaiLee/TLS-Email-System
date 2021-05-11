CC = gcc
CXX = g++

INCLUDES =

CFLAGS = -g -Wall -Wno-write-strings
CXXFLAGS = -g -Wall -Wno-write-strings

LDFLAGS = -g  -lcrypto

LDLIBS = -L/usr/lib -lcrypto 

server:
	g++ -g -Wall -o server server.cpp -L/usr/lib -lssl -lcrypto 

sendmsg:
	g++ -g -Wall -o sendmsg sendmsg.cpp -L/usr/lib -lssl -lcrypto

recvmsg:
	g++ -g -Wall -o recvmsg recvmsg.cpp -L/usr/lib -lssl -lcrypto
.PHONY: clean
clean:
	rm -f *.txt *.o a.out server recvmsg sendmsg

.PHONY: test
test: clean server recvmsg sendmsg

