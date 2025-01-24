
all:
	gcc -g -Wall -Wno-unused-variable *.c -lpcap -o udxcap
