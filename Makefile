
all:
	gcc -g -Wall -Werror -Wno-unused-variable *.c -o udxcap
	sudo setcap cap_net_raw,cap_net_admin+eip ./udxcap
