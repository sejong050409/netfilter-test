all: netfilter-test

netfilter-test: main.o
	gcc -o netfilter-test main.o -lnetfilter_queue

main.o: main.c headers.h
	gcc -c -o main.o main.c

clean:
	rm -f netfilter-test
	rm -f *.o
