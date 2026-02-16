# eBPF Learning Lab (Docker on Mac)

This repository contains a complete development environment for writing and running eBPF programs using Golang.

Because eBPF requires a Linux Kernel, this project runs inside a Docker container with special privileges.

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
