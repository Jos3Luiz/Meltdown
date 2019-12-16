

all:
	gcc  -o string stringGenerator.c
	gcc  -o meltdown meltdown.c -msse2 -O2
	#objdump -M intel -d ./meltdown
