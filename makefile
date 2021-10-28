CC= g++
CFLAGS= -c -g
LIB= -lcrypto -lpthread -lrt

all: client server

server.o: source_server/server_utils.cpp source_server/server_authentication.cpp source_server/server.cpp
	$(CC) $(CFLAGS) source_server/server.cpp

client.o: source_client/client_utils.cpp source_client/client_authentication.cpp source_client/client.cpp
	$(CC) $(CFLAGS) source_client/client_utils.cpp source_client/client_authentication.cpp source_client/client.cpp

secure.o: secure.cpp
	$(CC) $(CFLAGS) secure.cpp

util.o: util.cpp
	$(CC) $(CFLAGS) util.cpp

server: source_server/server.o source_server/server_utils.o source_server/server_authentication.o
	$(CC) source_server/server.o util.o secure.o source_server/server_utils.o source_server/server_authentication.o $(LIB) -o server

client: source_client/client.o util.o secure.o source_client/client_utils.o source_client/client_authentication.o
	$(CC) source_client/client.o util.o secure.o source_client/client_utils.o source_client/client_authentication.o $(LIB) -o client

clean:
	rm *.o client server source_client/*.o source_server/*.o
