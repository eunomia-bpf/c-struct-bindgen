# struct-bindgen

Generate C struct bindings between Wasm modules and host env/eBPF programs

## Usage

1. Create a C struct header, for example:

```c
#ifndef __SIGSNOOP_H
#define __SIGSNOOP_H

#define TASK_COMM_LEN	16

struct event {
	unsigned int pid;
	unsigned int tpid;
	int sig;
	int ret;
	char comm[TASK_COMM_LEN];
};

#endif /* __SIGSNOOP_H */
```