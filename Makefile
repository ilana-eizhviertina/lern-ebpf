.PHONY: init run-trace run-xdp run-tc clean start format

init:
	-go mod init learn-ebpf
	go get github.com/cilium/ebpf/cmd/bpf2go
	go mod tidy

run-trace:
	@echo "=> Building and running tracepoint..."
	cd tracepoint && go generate ./...
	go build -o app-tracepoint ./tracepoint
	./app-tracepoint

run-xdp:
	@echo "=> Building and running XDP..."
	cd xdp && go generate ./...
	go build -o app-xdp ./xdp
	./app-xdp

run-tc:
	@echo "=> Building and running TC..."
	cd tc && go generate ./...
	go build -o app-tc ./tc
	./app-tc

clean:
	rm -f app-*
	rm -rf tracepoint/gen/* xdp/gen/* tc/gen/*

start:
	docker run -it --rm --privileged \
  		-v $$(pwd):/code \
  		-v /sys/kernel/debug:/sys/kernel/debug \
  		ebpf-lab bash