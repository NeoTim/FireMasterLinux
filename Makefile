all: firemaster

firemaster: lowpbe.o sha_fast.o firemaster_main.o des.o KeyDBCracker.o
	g++ firemaster_main.o KeyDBCracker.o des.o sha_fast.o lowpbe.o -o firemaster_linux

KeyDBCracker.o: KeyDBCracker.cpp
	g++ -c KeyDBCracker.cpp

des.o: des.cpp
	g++ -c des.cpp

lowpbe.o: lowpbe.cpp
	g++ -c lowpbe.cpp

sha_fast.o: sha_fast.cpp
	g++ -c sha_fast.cpp

firemaster_main.o: firemaster_main.cpp
	g++ -c firemaster_main.cpp

clean:
	rm -rf *.o firemaster

