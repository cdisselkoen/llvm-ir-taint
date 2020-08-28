CC=clang-9
CXX=$$LLVM9PATH/bin/clang++
CFLAGS=-O0

.PHONY: all
all: struct.bc struct.ll \

%.ll : %.c
	$(CC) $(CFLAGS) -S -emit-llvm $^ -o $@

%.bc : %.c
	$(CC) $(CFLAGS) -c -emit-llvm $^ -o $@

%.ll : %.cpp
	$(CXX) $(CFLAGS) -S -emit-llvm $^ -o $@

%.bc : %.cpp
	$(CXX) $(CFLAGS) -c -emit-llvm $^ -o $@

.PHONY: clean
clean:
	find . -name "*.ll" | xargs rm
	find . -name "*.bc" | xargs rm
	find . -name "*~" | xargs rm
