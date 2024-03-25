#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "taskpermission.h"

typedef unsigned int u32;
typedef int pid_t;
const pid_t pid_filter = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
//suspend the current task
bpf_send_signal(19);
//bpf_send_signal(18);
struct event *e;
unsigned fname_off;
struct task_struct *task;
e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
if (!e)
	return 0;
task = (struct task_struct *)bpf_get_current_task();
pid_t pid = bpf_get_current_pid_tgid() >> 32;
if (pid_filter && pid != pid_filter)
  	return 0;
e->pid = pid;
e->ppid = BPF_CORE_READ(task, real_parent, tgid);
bpf_get_current_comm(&e->comm, sizeof(e->comm));

fname_off = ctx->__data_loc_filename & 0xFFFF;
bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

/* successfully submit it to user-space for post-processing */
bpf_ringbuf_submit(e, 0);
return 0;
}