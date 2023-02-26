HEADERS=log.h mptcp_util.h

default: all

all: client server

# Client clauses
client.o: client.c 
	gcc -c client.c -o client.o

client: client.o
	gcc client.o -o client

# Server clauses
server.o: server.c 
	gcc -c server.c -o server.o

server: server.o $(HEADERS)
	gcc server.o -o server

clean:
	-rm -f client.o
	-rm -f client
	-rm -f server.o
	-rm -f server
