.SUFFIXES = .c .o
CC = gcc

INC = -I/usr/include/libnl3
CFLAGS = -Wall -D_REVISION=0 $(INC)
LIBS = -lssl -lcrypto -lpcap

all : airdecap-ng.o airdecap-ng

airdecap-ng.o : airdecap-ng.c
	$(CC) $(CFLAGS) -c -o $@ airdecap-ng.c

airdecap-ng : airdecap-ng.o common.o crypto.o
	$(CC) -o $@ airdecap-ng.o common.o crypto.o $(LIBS)

clean :
	rm -rf $(OBJS) $(TARGET) core

new :
	$(MAKE) clean
	$(MAKE)
