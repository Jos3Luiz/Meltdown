

all:
	gcc -Wall -o exp2 exp2.c -O0
	#objdump -M intel -d ./exp
	./exp2
