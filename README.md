# eBPF Learning Lab

This repository contains a complete development environment for writing and running eBPF programs using Golang.

📚 Learning Resource:
I am building this repository while learning from the book "Learning eBPF" by Liz Rice. I use her examples as a foundation, implementing them in Go and extending them with my own custom additions and logic. Please note that in some places, the implementation varies significantly from the book.

---

## The Environment (Dockerfile Overview)

The Dockerfile creates a "trace-ready" Linux environment. Here is what it does:

* **Base Image:** Uses `ubuntu:22.04` as the foundation.
* **Dependencies:** Installs `clang`, `llvm`, and `libbpf-dev` (required to compile C code into BPF bytecode).
* **Kernel Headers:** Installs `linux-headers-generic` and creates a symbolic link so the compiler can find them (`asm/types.h`).
* **Go Installation:** Automatically detects your architecture.
* **BPF Tool:** Manually installs `bpftool v7.5.0` (essential for inspecting the kernel) to avoid version mismatches on Mac Docker.

---

## Project Structure

This lab is designed to hold multiple eBPF programs. Each program gets its own folder:

* `/tracepoint` - A program that hooks into kernel system calls.
* `/xdp` - A program that acts as a low-level network firewall.

---

## How to Build the Lab

Open your terminal in this folder and run:

```bash
docker build -t ebpf-lab .
```

Once built, start the privileged container:

```bash
make start
```

## 🏃‍♂️ How to Run the Code

Once you are inside the container (e.g., root@...:/code#), follow these steps:

Step A: Initialize (First Time Only)

If you haven't initialized the Go module yet:
```bash
make init
```

Step B: Build & Run
To compile the C code, generate the Go bindings, build the Go binary, and start the application, run the following commands based on the lab you want to use:

1) To run the Tracepoint lab:
```bash
export GOTOOLCHAIN=local
make run APP=tracepoint
```

2) To run the XDP lab:
```bash
export GOTOOLCHAIN=local
make run APP=xdp
```

## How to View the Logs

If an app uses bpf_printk, you need a second terminal to see the kernel logs.

Find your container ID:
```bash
docker ps
docker exec -it <container_id> bash
cat /sys/kernel/debug/tracing/trace_pipe
```
