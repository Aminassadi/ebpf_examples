#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "ptrace_terminator.skel.h"
#include "ptrace_terminator.h"
#include <unistd.h>
#include <signal.h>

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
    printf("%-16s %-7d %s\n", e->comm, e->pid, e->success ? "true" : "false");    
	return 0;
}

int main()
{
    struct ring_buffer *rb = NULL;
	struct ptrace_terminator_bpf *skel;
	int err;	

    signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	/* Set up libbpf errors and debug info callback */

	/* Load and verify BPF application */
	skel = ptrace_terminator_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}


    err = ptrace_terminator_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    err = ptrace_terminator_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    printf("%-16s %-7s %-10s\n", "filename", "pid", "blocked");
    while (!exiting) {
            err = ring_buffer__poll(rb, 100 /* timeout, ms */);
            /* Ctrl-C will cause -EINTR */
            if (err == -EINTR) {
                err = 0;
                break;
            }
            if (err < 0) {
                printf("Error polling perf buffer: %d\n", err);
                break;
            }
    }

    cleanup:
	/* Clean up */
	ptrace_terminator_bpf__destroy(skel);
	return err < 0 ? -err : 0;

}