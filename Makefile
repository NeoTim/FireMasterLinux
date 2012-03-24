GCC_FLAGS = -O2 -Wall `pkg-config --cflags nss` `pkg-config --cflags openssl`
LD_FLAGS = `pkg-config --libs openssl` `pkg-config --libs nss` -lm

all: firemaster

firemaster: lowpbe.o firemaster_main.o des.o KeyDBCracker.o
	gcc $(GCC_FLAGS) firemaster_main.o KeyDBCracker.o des.o lowpbe.o -o firemaster_linux $(LD_FLAGS)
	make clean_intermediates

KeyDBCracker.o: KeyDBCracker.c
	gcc $(GCC_FLAGS) -c KeyDBCracker.c

des.o: des.c
	gcc $(GCC_FLAGS) -c des.c

lowpbe.o: lowpbe.c
	gcc $(GCC_FLAGS) -c lowpbe.c

firemaster_main.o: firemaster_main.c
	gcc $(GCC_FLAGS) -c firemaster_main.c

clean_intermediates:
	rm -rf *.o

clean:
	rm -f firemaster_linux *.o
