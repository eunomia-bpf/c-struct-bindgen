.PHONY: generate-headers all
all: generate-headers

# generate headers for each bpf.o file
TEST_CASES=$(shell ls -l *.bpf.o | awk '{print $$9}')
generate-headers: $(TEST_CASES)

.PHONY:$(TEST_CASES)
# build the test cases
$(TEST_CASES):
	../../build/bin/Debug/struct-bindgen $@ > $@.binding.h

