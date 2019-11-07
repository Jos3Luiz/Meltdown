

all:
	gcc -Wall -o meltdown meltdownPoc.c -O0
	#objdump -M intel -d ./exp
	./meltdown
