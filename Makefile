# Makefile for Writing Make Files Example

# *****************************************************
# Variables to control Makefile operation

CC = gcc
CFLAGS = -Wall -g -Wextra -lseccomp
#LDFLAGS=-lpthread
RM=/bin/rm

# ****************************************************
# Targets needed to bring the executable up to date

main: main.o dumbbox.o
	$(CC) $(CFLAGS) -o main main.o dumbbox.o $(CFLAGS)

main.o: main.c
	$(CC) $(CFLAGS) -c main.c $(CDFLAGS)

dumbbox.o: dumbbox.c
	$(CC) $(CFLAGS) -c dumbbox.c $(CDFLAGS)	

clean:
	$(RM) main *.o