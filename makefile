

all:
	gcc -o exp exp.c
	objdump -M intel -d ./exp
	./exp
