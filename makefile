

all:
	gcc  -o string stringGenerator.c
	gcc  -o meltdown meltdown.c -O0 -m64
	#objdump -M intel -d ./meltdown
