.PHONY: build

build:
		go build -o build/go-first

clean:
		rm -rf build/*

run:
		./build/go-first
