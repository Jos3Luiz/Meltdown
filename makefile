

all:
	gcc  -o string stringGenerator.c
	gcc  -o meltdown meltdown.c -O0 -m32
	#objdump -M intel -d ./meltdown
