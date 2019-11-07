

all:
	gcc -Wall -o meltdown meltdownPoc.c -O0 -m64
	#objdump -M intel -d ./meltdown
	./meltdown
