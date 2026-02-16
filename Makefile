.PHONY: init run-trace run-xdp clean start

init:
	-go mod init learn-ebpf
	go get github.com/cilium/ebpf/cmd/bpf2go
	go mod tidy

# Shortcut to build and run the tracepoint program
run-trace:
	@echo "=> Building and running tracepoint..."
	cd tracepoint && go generate ./...
	go build -o app-tracepoint ./tracepoint
	./app-tracepoint

# Shortcut to build and run the XDP program
run-xdp:
	@echo "=> Building and running XDP..."
	cd xdp && go generate ./...
	go build -o app-xdp ./xdp
	./app-xdp

clean:
	rm -f app-tracepoint app-xdp
	rm -rf tracepoint/gen/* xdp/gen/*

start:
	docker run -it --rm --privileged \
  		-v $$(pwd):/code \
  		-v /sys/kernel/debug:/sys/kernel/debug \
  		ebpf-lab bash