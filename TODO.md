# OS-Level Defense Backlog

The guard-branch static analysis (content scanning, bash-command interception) catches the most common bypass patterns. However, a pre-compiled binary with a hardcoded or runtime-constructed target path cannot be caught by command-string analysis alone. The following OS-level tools close that gap.

## Tools to Investigate

### auditd (Linux Audit Daemon)
Monitor `open(2)` syscalls with write flags (`O_WRONLY`, `O_RDWR`, `O_TRUNC`, `O_CREAT`) targeting the protected repository directory. Any process — regardless of how it was invoked — that opens a file under the guarded path for writing triggers an audit event.

Example rule:
```
auditctl -w /home/user/project -p w -k guardrails-write
```

Reference: https://github.com/linux-audit/audit-userspace

### inotify-tools (Linux)
Filesystem event watcher. A daemon can watch the protected repo directory and alert or kill the writing process when an unexpected write event is detected.

Reference: https://github.com/inotify-tools/inotify-tools

### AppArmor / SELinux (Mandatory Access Control)
Deny write access to the protected repo directory for all processes except an explicit allowlist. This is the gold standard — it enforces at the kernel level and cannot be bypassed by any userspace technique.

- **AppArmor**: write a profile that denies `w` access to the repo path for the Claude Code process group.
- **SELinux**: create a policy module restricting write access by process label.

### eBPF-based Tools (Falco, Tetragon)
Kernel-level observability with low overhead. Can detect anomalous write syscalls by any process and generate alerts or enforcing actions.

- **Falco**: https://github.com/falcosecurity/falco — rule-based runtime security, integrates with existing alerting pipelines.
- **Tetragon** (Cilium): https://github.com/cilium/tetragon — eBPF-based with enforcement capabilities (SIGKILL on policy violation).

## Priority Order

1. **auditd** — lowest friction to set up, good audit trail, non-enforcing (alerting only)
2. **AppArmor / SELinux** — enforcing, covers all processes, requires OS support
3. **Falco / Tetragon** — most flexible and observable, best for complex environments
4. **inotify-tools** — useful for prototyping / lightweight setups
