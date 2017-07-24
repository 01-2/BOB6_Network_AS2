CC = gcc
AS2 : AS2.c
	gcc -o AS2 AS2.c -lpcap
clean :
	rm AS2
