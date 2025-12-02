CXX = g++
CXXFLAGS = -Wall -std=c++17
LIBS = -lpcap

OBJS = src/networkScanner.o src/hostReconLib.o

networkScanner: $(OBJS)
	$(CXX) $(OBJS) $(LIBS) -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) networkScanner
