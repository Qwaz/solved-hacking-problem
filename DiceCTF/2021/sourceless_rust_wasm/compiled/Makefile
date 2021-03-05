.PHONY: all clean

all: wasmpwn.so

wasmpwn.so: wasmpwn.c
	gcc $^ -m32 -Wno-builtin-declaration-mismatch -std=c99 -fPIC --shared -o $@

wasmpwn.c: ../wasmpwn.wasm
	wasm2c $^ -o $@

clean:
	rm -f wasmpwn.so wasmpwn.c
