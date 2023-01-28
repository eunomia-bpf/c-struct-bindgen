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

struct event2 {
	void* unused_ptr;
	float x;
	double y;
	int z;
	long long int a;
	short comm[TASK_COMM_LEN];
};

struct event3 {
	struct event2 e2;
	double g;
};

#endif /* __SIGSNOOP_H */
