.PHONY: all clean

all: table_gen

table_gen: table_gen.cpp
	g++ $^ -lgmp -fopenmp -o $@

clean:
	rm -f table_gen table
