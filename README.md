# **libbpf-starter-template**

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
[![Build and publish](https://github.com/eunomia-bpf/libbpf-starter-template/actions/workflows/publish.yml/badge.svg)](https://github.com/eunomia-bpf/libbpf-starter-template/actions/workflows/publish.yml)

use **`libbpf-starter-template`**! This project template is designed to help you quickly start
developing eBPF projects using libbpf in C. The template provides a solid starting point with a Makefile, 
Dockerfile, and GitHub action, along with all necessary dependencies to simplify your development process.
for more detail: *https://github.com/eunomia-bpf/libbpf-starter-template*

### **1. Install dependencies**

For dependencies, it varies from distribution to distribution. You can refer to shell.nix and dockerfile for installation.

On Ubuntu, you may run `make install` or

```sh
sudo apt-get install -y --no-install-recommends \
        libelf1 libelf-dev zlib1g-dev \
        make clang llvm
```

to install dependencies.

### **2. Build the project**

To build the project, run the following commands:

```sh
git submodule update --init --recursive
make 
```

### ***Run the Project***

You can run the binary with:

```console
sudo src/.bin/bootstrap
```

## **Contributing**

We welcome contributions to improve this template! If you have any ideas or suggestions,
feel free to create an issue or submit a pull request.

## **License**

This project is licensed under the MIT License. See the **[LICENSE](LICENSE)** file for more information.
