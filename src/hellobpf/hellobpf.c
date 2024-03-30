#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "skeleton/hellobpf.skel.h"
#include <unistd.h>

static volatile bool exiting = false;
int main()
{
	struct hello_bpf *skel;
	int err;	

	/* Set up libbpf errors and debug info callback */

	/* Load and verify BPF application */
	skel = hellobpf_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}


    err = hellobpf_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    err = hellobpf_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
    printf("starting\n");
    while (!exiting) {
		usleep(1000);
	}

    cleanup:
	/* Clean up */
	hellobpf_bpf__destroy(skel);
	return err < 0 ? -err : 0;

}