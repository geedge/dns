all:
	gcc -Wall -g -fPIC -shared -I./include/ ./dns_test.c -o dns_test.so 
	cp ./dns_test.so ../bin/
clean:
	rm -rf *.o *.so
