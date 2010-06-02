XUL_INCLUDE = -I/home/chris/Documents/RNP/xulrunner-sdk/include/
XUL_LIB = -L/home/chris/Documents/RNP/xulrunner-sdk/lib/
GCC_FLAGS = -O5

all: firemaster

firemaster: lowpbe.o sha_fast.o firemaster_main.o des.o KeyDBCracker.o
	g++ $(GCC_FLAGS) $(XUL_LIB) $(XUL_INCLUDE) firemaster_main.o KeyDBCracker.o des.o sha_fast.o lowpbe.o -o firemaster_linux
	make clean_intermediates	

KeyDBCracker.o: KeyDBCracker.cpp
	g++ $(GCC_FLAGS) $(XUL_LIB) $(XUL_INCLUDE) -c KeyDBCracker.cpp

des.o: des.cpp
	g++ $(GCC_FLAGS) $(XUL_LIB) $(XUL_INCLUDE) -c des.cpp

lowpbe.o: lowpbe.cpp
	g++ $(GCC_FLAGS) $(XUL_LIB) $(XUL_INCLUDE) -c lowpbe.cpp

sha_fast.o: sha_fast.cpp
	g++ $(GCC_FLAGS) $(XUL_LIB) $(XUL_INCLUDE) -c sha_fast.cpp

firemaster_main.o: firemaster_main.cpp
	g++ $(GCC_FLAGS) $(XUL_LIB) $(XUL_INCLUDE) -c firemaster_main.cpp

clean_intermediates:
	rm -rf *.o

clean:
	rm -f firemaster_linux
