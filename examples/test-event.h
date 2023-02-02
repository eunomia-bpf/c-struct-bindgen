//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
#ifndef __SIGSNOOP_H
#define __SIGSNOOP_H

#define TASK_COMM_LEN 16

struct event {
    unsigned int pid;
    unsigned int tpid;
    int sig;
    int ret;
    char comm[TASK_COMM_LEN];
};

struct event2 {
    char b;
    float x;
    double y;
    int z;
    long long int a;
    short comm[TASK_COMM_LEN];
    void *unused_ptr;
    char end;
};

struct event3 {
    struct event2 e2;
    double g;
};

#endif /* __SIGSNOOP_H */
