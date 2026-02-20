# Rego policy for sysadmin AI
# This is the default policy used by OPA

package sysadmin

import future.keywords.if
import future.keywords.in

# Default deny
default allow := false

# Allow read-only commands
allow if {
    input.command in ["ls", "cat", "grep", "find", "ps", "df", "du", "top", "free", "uname", "whoami", "pwd", "echo", "head", "tail", "less", "more", "wc", "sort", "uniq", "awk", "sed"]
}

# Allow if command starts with safe prefix
allow if {
    safe_prefixes := ["ls ", "cat ", "grep ", "find ", "ps ", "df ", "du ", "top ", "htop", "free", "uname ", "whoami", "pwd", "echo ", "head ", "tail ", "less ", "more ", "wc ", "sort ", "uniq ", "awk ", "sed ", "which ", "whereis ", "file ", "stat ", "lsblk", "lscpu", "lsmem", "lsusb", "lspci", "lsmod", "hostname", "uptime", "date", "cal"]
    some prefix
    startswith(lower(input.command), safe_prefixes[prefix])
}

# Block destructive commands
block_patterns := [
    "rm -rf /",
    "rm -rf /*",
    "mkfs",
    "dd if=/dev/zero",
    "dd if=/dev/random",
    ":(){ :|:& };:",
    "> /dev/sda",
    "> /dev/hda",
    "mv / /dev/null"
]

deny if {
    some pattern
    block_patterns[pattern]
    contains(lower(input.command), block_patterns[pattern])
}

# Block if running as root and command is risky
risky_patterns := ["rm -rf", "mkfs", "fdisk", "parted"]

deny if {
    input.user == "root"
    some pattern
    risky_patterns[pattern]
    contains(lower(input.command), risky_patterns[pattern])
}

# Allow if not denied and matches allow rules
allow if {
    not deny
    input.executor_type == "host"
}

# Docker-specific rules
allow if {
    not deny
    input.executor_type == "docker"
    not contains(lower(input.command), "docker.sock")
    not contains(lower(input.command), "/var/run/docker")
}

# Kubernetes-specific rules
allow if {
    not deny
    input.executor_type == "kubernetes"
    not contains(lower(input.command), "kubectl delete namespace")
    not contains(lower(input.command), "kubectl delete node")
}
