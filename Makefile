CC = gcc
CFLAGS = -lcrypto -lssl 

all: echoClientMake echoServerMake

echoClientMake: echoClient.c
	$(CC) echoClient.c $(CFLAGS) -o echoClient

echoServerMake: echoServer.c
	$(CC) echoServer.c $(CFLAGS) -o echoServer

clean:
	rm -f echoServer echoClient
