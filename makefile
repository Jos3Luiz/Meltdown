

all:
	gcc -Wall -o exp2 exp2.c
	#objdump -M intel -d ./exp
	./exp2
