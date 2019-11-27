

all:
	gcc  -o string stringGenerator.c
	gcc  -o meltdown meltdown.c -O0
	#objdump -M intel -d ./meltdown
