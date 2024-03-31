#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
//this part is compeletly copied from linux/user.h 
//I now I put this shit here forgive me
#if !(__GNUC_PREREQ (2,8) || defined __clang__)
# define __extension__		/* Ignore */
#endif

struct user_regs_struct
{
  __extension__ unsigned long long int r15;
  __extension__ unsigned long long int r14;
  __extension__ unsigned long long int r13;
  __extension__ unsigned long long int r12;
  __extension__ unsigned long long int rbp;
  __extension__ unsigned long long int rbx;
  __extension__ unsigned long long int r11;
  __extension__ unsigned long long int r10;
  __extension__ unsigned long long int r9;
  __extension__ unsigned long long int r8;
  __extension__ unsigned long long int rax;
  __extension__ unsigned long long int rcx;
  __extension__ unsigned long long int rdx;
  __extension__ unsigned long long int rsi;
  __extension__ unsigned long long int rdi;
  __extension__ unsigned long long int orig_rax;
  __extension__ unsigned long long int rip;
  __extension__ unsigned long long int cs;
  __extension__ unsigned long long int eflags;
  __extension__ unsigned long long int rsp;
  __extension__ unsigned long long int ss;
  __extension__ unsigned long long int fs_base;
  __extension__ unsigned long long int gs_base;
  __extension__ unsigned long long int ds;
  __extension__ unsigned long long int es;
  __extension__ unsigned long long int fs;
  __extension__ unsigned long long int gs;
};

int main(int argc, char *argv[]) {
    pid_t traced_process;
    struct user_regs_struct regs;

    if (argc != 2) {
        printf("Usage: %s <pid to be traced>\n", argv[0]);
        exit(1);
    }

    traced_process = atoi(argv[1]);
    printf("starting...\n");
    // Attach to the process
    if (ptrace(PTRACE_ATTACH, traced_process, NULL, NULL) == -1) {
        perror("ptrace(PTRACE_ATTACH)");
        exit(1);
    }
    printf("successfully attached to the process\n");
    // Wait for the process to stop
    wait(NULL);

    // Get the process's registers
    if (ptrace(PTRACE_GETREGS, traced_process, NULL, &regs) == -1) {
        perror("ptrace(PTRACE_GETREGS)");
        exit(1);
    }

    printf("EIP: %lx\n", regs.rip);

    // Detach from the process
    if (ptrace(PTRACE_DETACH, traced_process, NULL, NULL) == -1) {
        perror("ptrace(PTRACE_DETACH)");
        exit(1);
    }

    return 0;
}
