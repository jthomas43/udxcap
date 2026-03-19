
all:
	gcc -g -Wall -Wno-unused-variable *.c -lpcap -o udxcap
	sudo setcap cap_net_raw,cap_net_admin+eip ./udxcap


