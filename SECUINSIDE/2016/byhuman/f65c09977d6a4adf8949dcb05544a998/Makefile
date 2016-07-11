MAKEFLAGS := -j5
CXXFLAGS := -std=c++11 -Wall -O2 -m32 -g
OBJS = main.o storage.o string.o number.o item.o functions.o interpreter.o
HEADERS = std.h common.h
CXX = g++
DEPS = *.h Makefile

all: bh

bh: prepare_random_padding $(OBJS)
	$(CXX) $(OBJS) -o bh -m32 $(CXXFLAGS)

%.o: %.cc $(DEPS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

prepare_random_padding:
	python random_padding.py &

clean:
	rm $(OBJS) bh