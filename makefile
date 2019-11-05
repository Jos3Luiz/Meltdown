

all:
	gcc -Wall -o exp exp.c
	#objdump -M intel -d ./exp
	./exp
