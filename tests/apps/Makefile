.PHONY: clean all

all: bin/time bin/time_namespace;

bin:
	mkdir $@

bin/time: time.c | bin
	gcc $< -ldl -o $@

bin/time_namespace: time_namespace.c | bin
	gcc $< -o $@

clean:
	rm -rf bin
