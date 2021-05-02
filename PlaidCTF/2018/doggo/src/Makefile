all: wolf-lang

wolf-lang: sources.mlb bigint.c *.sml
	mlton                                    \
    -mlb-path-var "MLTON_LIB ${MLTON_LIB}" \
    -output wolf-lang                      \
    -codegen native                        \
    -runtime "fixed-heap 16M"              \
    -runtime "hash-cons 0.2"               \
    -export-header mlton_types.h           \
    -link-opt '${CTTK}/build/libcttk.a'    \
    -cc-opt '-I${CTTK}/inc'                \
    sources.mlb bigint.c

bigint.c sources.mlb:

%.sml:

clean:
	rm -rf wolf-lang mlton_types.h

.PHONY: all
