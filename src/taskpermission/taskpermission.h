#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define MAX_FILENAME_LEN 127
#define TASK_COMM_LEN 16

struct event {
	int pid;
	int ppid;	
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
};
#endif