XUL_INCLUDE = -I/home/[user]/xulrunner-sdk/include/
XUL_LIB = -L/home/[user]/xulrunner-sdk/lib/

all: firemaster

firemaster: lowpbe.o sha_fast.o firemaster_main.o des.o KeyDBCracker.o
	g++ $(XUL_LIB) $(XUL_INCLUDE) firemaster_main.o KeyDBCracker.o des.o sha_fast.o lowpbe.o -o firemaster_linux
	make clean_intermediates	

KeyDBCracker.o: KeyDBCracker.cpp
	g++ $(XUL_LIB) $(XUL_INCLUDE) -c KeyDBCracker.cpp

des.o: des.cpp
	g++ $(XUL_LIB) $(XUL_INCLUDE) -c des.cpp

lowpbe.o: lowpbe.cpp
	g++ $(XUL_LIB) $(XUL_INCLUDE) -c lowpbe.cpp

sha_fast.o: sha_fast.cpp
	g++ $(XUL_LIB) $(XUL_INCLUDE) -c sha_fast.cpp

firemaster_main.o: firemaster_main.cpp
	g++ $(XUL_LIB) $(XUL_INCLUDE) -c firemaster_main.cpp

clean_intermediates:
	rm -rf *.o

clean:
	rm -f firemaster_linux
	rm -rf *.o
