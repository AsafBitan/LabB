all: BSort

BSort: BubbleSort.o hexaPrint.o
	cc -g -m32 -Wall -o BSort BubbleSort.o hexaPrint.o

BubbleSort.o: BubbleSort.c
	gcc -m32 -g -Wall -c -o BubbleSort.o BubbleSort.c

hexaPrint.o: hexaPrint.c
	gcc -m32 -g -Wall -c -o hexaPrint.o hexaPrint.c
	
.PHONY: clean

clean:
	rm -f *o BSort
