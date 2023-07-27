all: pvm

pvm: pvm.c
	gcc -Wall -g -o pvm pvm.c

clean: 
	rm -fr pvm *~ *.o