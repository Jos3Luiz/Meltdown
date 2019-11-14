

all:
	g++ -Wall -o meltdown meltdownPoc3.c -O0 -m64
	#objdump -M intel -d ./meltdown
	./meltdown
