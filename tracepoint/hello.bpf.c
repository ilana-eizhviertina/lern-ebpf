//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Define "u32" so we can use it (standard kernel shortcut)
typedef unsigned int u32;

// Define the MAP (The Database)
struct {
    __uint(type, BPF_MAP_TYPE_HASH); // Hash Map (Key/Value store)
    __uint(max_entries, 1024);       // Can hold 1024 different Users
    __type(key, u32);                // Key = UID (User ID)
    __type(value, u32);              // Value = Counter
} exec_counts SEC(".maps");

// The Program
SEC("tp/syscalls/sys_enter_execve")
int hello_world(void *ctx) {
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    u32 *val;
    u32 init_val = 1;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("EXEC: Name=%s PID=%d UID=%d", comm, pid, uid);

    // LOOKUP: Does this UID exist in the map?
    val = bpf_map_lookup_elem(&exec_counts, &uid);

    if (val) {
        // Yes: Increment the existing counter safely
        __sync_fetch_and_add(val, 1);
    } else {
        // No: Create a new entry for this UID with value 1
        bpf_map_update_elem(&exec_counts, &uid, &init_val, BPF_ANY);
    }

    return 0;
}
