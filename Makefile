GCC_FLAGS = -O5 -Wall `pkg-config --cflags nss` `pkg-config --cflags openssl`
LD_FLAGS = `pkg-config --libs openssl` `pkg-config --libs nss`

all: firemaster

firemaster: lowpbe.o firemaster_main.o des.o KeyDBCracker.o
	g++ $(GCC_FLAGS) firemaster_main.o KeyDBCracker.o des.o lowpbe.o -o firemaster_linux $(LD_FLAGS)
	make clean_intermediates

KeyDBCracker.o: KeyDBCracker.cpp
	g++ $(GCC_FLAGS) -c KeyDBCracker.cpp

des.o: des.cpp
	g++ $(GCC_FLAGS) -c des.cpp

lowpbe.o: lowpbe.cpp
	g++ $(GCC_FLAGS) -c lowpbe.cpp

firemaster_main.o: firemaster_main.cpp
	g++ $(GCC_FLAGS) -c firemaster_main.cpp

clean_intermediates:
	rm -rf *.o

clean:
	rm -f firemaster_linux *.o
