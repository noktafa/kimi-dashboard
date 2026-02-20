"""Safety filters for blocking dangerous commands."""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class SafetyLevel(Enum):
    """Safety classification levels."""
    SAFE = "safe"
    GRAY = "gray"  # Requires confirmation
    BLOCK = "block"  # Always blocked


@dataclass
class SafetyResult:
    """Result of safety check."""
    level: SafetyLevel
    reason: str
    command: str


class SafetyFilter:
    """Filter commands for safety."""
    
    # Destructive patterns - ALWAYS BLOCKED
    BLOCKLIST = [
        # Mass deletion
        r'rm\s+-[a-zA-Z]*r[a-zA-Z]*\s+/',
        r'rm\s+-[a-zA-Z]*r[a-zA-Z]*\s+--',
        r'rm\s+-[a-zA-Z]*f[a-zA-Z]*\s+/',
        r'rm\s+.*\*.*',
        r'rm\s+-rf\s+\.',
        r'rm\s+-rf\s+~',
        r'rm\s+-rf\s+/',
        
        # Filesystem destruction
        r'mkfs\.\w+\s+/dev/',
        r'mkfs\s+/dev/',
        r'newfs\s+/dev/',
        
        # Direct disk writes
        r'dd\s+.*of=/dev/[sh]d[a-z]',
        r'dd\s+.*of=/dev/nvme',
        r'dd\s+.*of=/dev/mmcblk',
        r'dd\s+.*of=/dev/disk',
        r'dd\s+.*of=/dev/zero.*of=/dev/',
        
        # Partition manipulation
        r'fdisk\s+/dev/',
        r'parted\s+/dev/',
        r'gparted',
        r'pvcreate\s+/dev/',
        r'vgremove',
        r'lvremove',
        
        # System destruction
        r':\(\)\s*\{\s*:\|:\s*&\s*\};\s*:',  # Fork bomb
        r'char\s+\w+\[\]\s*=\s*"\\x[0-9a-f]',  # Hex encoded shellcode
        
        # Reverse shells
        r'bash\s+-i\s*>&\s*/dev/tcp/',
        r'sh\s+-i\s*>&\s*/dev/tcp/',
        r'nc\s+-[a-zA-Z]*e[a-zA-Z]*\s+.*\d+',
        r'ncat\s+-[a-zA-Z]*e[a-zA-Z]*\s+',
        r'python\d*\s+-c\s*.*socket.*connect',
        r'python\d*\s+-c\s*.*subprocess.*socket',
        r'ruby\s+-rsocket\s+-e',
        r'perl\s+-MIO::Socket',
        r'php\s+-r\s*.*fsockopen',
        r'lua\s+-e\s*.*socket',
        r'socat\s+.*exec:',
        r'socat\s+.*tcp-connect:',
        r'mkfifo\s+.*sh\s+-i',
        r'/bin/sh\s+-i\s*<\s*.*>\s*/dev/tcp/',
        r'0<&196;exec\s+196<>/dev/tcp/',
        r'exec\s+/bin/sh\s+0</dev/tcp/',
        
        # Credential access
        r'cat\s+/etc/shadow',
        r'cat\s+/etc/master\.passwd',
        r'cat\s+/etc/security/passwd',
        r'cat\s+/etc/sudoers',
        r'cat\s+/etc/ssh/sshd_config',
        r'cat\s+/root/\.ssh/',
        r'cat\s+/home/\w+/\.ssh/',
        r'cat\s+.*\.pem',
        r'cat\s+.*\.key',
        r'cat\s+.*\.p12',
        r'cat\s+.*\.pfx',
        r'cat\s+/var/log/secure',
        r'cat\s+/var/log/auth\.log',
        r'cat\s+/var/log/audit/',
        r'cat\s+/etc/krb5\.keytab',
        r'cat\s+/etc/ssl/private/',
        r'openssl\s+rsa\s+-in',
        r'openssl\s+dsa\s+-in',
        r'openssl\s+ec\s+-in',
        
        # AWS/GCP/Azure credentials
        r'cat\s+~/.aws/credentials',
        r'cat\s+~/.aws/config',
        r'cat\s+~/.config/gcloud/credentials',
        r'cat\s+~/.azure/credentials',
        r'cat\s+/root/.aws/',
        r'cat\s+/home/\w+/.aws/',
        r'aws\s+sts\s+get-session-token',
        r'gcloud\s+auth\s+print-access-token',
        r'az\s+account\s+get-access-token',
        
        # Database credential access
        r'cat\s+/var/lib/mysql/mysql\.user',
        r'cat\s+/etc/postgresql/\w+/pg_hba\.conf',
        r'cat\s+/var/lib/pgsql/data/pg_hba\.conf',
        r'cat\s+/etc/redis/redis\.conf',
        r'cat\s+/etc/mongodb\.conf',
        
        # History sniffing
        r'cat\s+/root/\.bash_history',
        r'cat\s+/root/\.zsh_history',
        r'cat\s+/home/\w+/\.bash_history',
        r'cat\s+/home/\w+/\.zsh_history',
        r'cat\s+/home/\w+/\.history',
        
        # Kernel/module manipulation
        r'rmmod\s+',
        r'modprobe\s+-r\s+',
        r'insmod\s+.*\.ko',
        r'kexec\s+',
        
        # Bootloader manipulation
        r'grub-install',
        r'lilo',
        r'efibootmgr\s+-[Bb]',
        
        # Hardware damage
        r'msr-safe',
        r'pci\s+write',
        r'ectool\s+flash',
        
        # Network exfiltration
        r'scp\s+.*@.*:/',
        r'rsync\s+.*@.*:/',
        r'curl\s+.*-F\s+.*@',
        r'curl\s+.*--data-binary',
        r'wget\s+.*--post-file',
        r'nc\s+.*<\s+/etc/',
        r'nc\s+.*<\s+/var/',
        r'nc\s+.*<\s+/home/',
        r'telnet\s+.*<\s+/etc/',
        
        # Encryption/locking
        r'cryptsetup\s+luksFormat',
        r'cryptsetup\s+luksErase',
        r'vconfig\s+rem',
    ]
    
    # Suspicious patterns - REQUIRE CONFIRMATION
    GRAYLIST = [
        # Package management
        r'apt\s+(install|remove|purge|autoremove)',
        r'apt-get\s+(install|remove|purge|autoremove)',
        r'dpkg\s+-[riP]',
        r'yum\s+(install|remove|erase)',
        r'dnf\s+(install|remove|erase)',
        r'pacman\s+-[RS]',
        r'zypper\s+(install|remove)',
        r'apk\s+(add|del)',
        r'pip\s+(install|uninstall)',
        r'pip3\s+(install|uninstall)',
        r'npm\s+(install|uninstall|remove)',
        r'gem\s+(install|uninstall)',
        r'cargo\s+(install|uninstall)',
        r'go\s+install',
        r'conda\s+(install|remove)',
        
        # Service management
        r'systemctl\s+(start|stop|restart|enable|disable)',
        r'service\s+\w+\s+(start|stop|restart)',
        r'initctl\s+(start|stop|restart)',
        r'rc-service\s+\w+\s+(start|stop|restart)',
        r'rc-update\s+(add|del)',
        
        # Network configuration
        r'ip\s+link\s+set',
        r'ip\s+addr\s+(add|del)',
        r'ip\s+route\s+(add|del)',
        r'ifconfig\s+\w+\s+(up|down)',
        r'route\s+(add|del)',
        r'iptables\s+-[AD]',
        r'nft\s+add',
        r'ufw\s+(enable|disable|allow|deny|delete)',
        r'firewall-cmd',
        
        # User management
        r'useradd',
        r'userdel',
        r'usermod',
        r'groupadd',
        r'groupdel',
        r'groupmod',
        r'passwd\s+\w+',
        r'chpasswd',
        
        # Permission changes
        r'chmod\s+-R\s+777',
        r'chmod\s+-R\s+666',
        r'chmod\s+777\s+/',
        r'chmod\s+666\s+/etc/',
        r'chown\s+-R\s+\w+:\w+\s+/',
        r'chown\s+\w+:\w+\s+/etc/',
        r'chattr\s+\+i',
        r'chattr\s+-i',
        
        # Filesystem operations
        r'mount\s+/dev/',
        r'umount\s+/',
        r'fsck\s+/dev/',
        r'tune2fs\s+/dev/',
        r'xfs_repair\s+/dev/',
        r'btrfs\s+filesystem',
        r'zfs\s+(create|destroy|rename)',
        r'zpool\s+(create|destroy)',
        
        # Container operations
        r'docker\s+(run|exec|rm|stop|kill)',
        r'docker\s+system\s+prune',
        r'kubectl\s+(delete|apply|exec)',
        r'kubectl\s+.*--force',
        r'nerdctl\s+(run|exec|rm)',
        r'podman\s+(run|exec|rm)',
        r'ctr\s+',
        
        # File operations that could be destructive
        r'>\s+/etc/',
        r'>\s+/var/',
        r'truncate\s+-s\s+0',
        r'cp\s+/dev/null',
        
        # Remote access
        r'ssh\s+.*@',
        r'sshpass\s+',
        r'rsync\s+-avz\s+.*:',
        
        # Process killing
        r'killall\s+',
        r'pkill\s+',
        r'kill\s+-9\s+',
        
        # System updates
        r'do-release-upgrade',
        r'apt\s+full-upgrade',
        r'apt-get\s+dist-upgrade',
        r'yum\s+update',
        r'dnf\s+system-upgrade',
        r'pacman\s+-Syu',
        
        # SELinux/AppArmor
        r'setenforce\s+0',
        r'setenforce\s+permissive',
        r'apparmor_parser\s+-R',
        
        # Kernel parameters
        r'sysctl\s+-w',
        r'echo\s+.*>\s+/proc/sys/',
        
        # Cron manipulation
        r'crontab\s+-[er]',
        r'echo\s+.*>\s+/etc/cron',
        
        # Sudo/su escalation
        r'sudo\s+-i',
        r'sudo\s+su',
        r'su\s+-',
    ]
    
    def __init__(self) -> None:
        """Initialize the safety filter."""
        self.block_patterns = [re.compile(p, re.IGNORECASE) for p in self.BLOCKLIST]
        self.gray_patterns = [re.compile(p, re.IGNORECASE) for p in self.GRAYLIST]
    
    def check(self, command: str) -> SafetyResult:
        """Check if a command is safe to execute.
        
        Args:
            command: The command to check
            
        Returns:
            SafetyResult with the safety level and reason
        """
        command = command.strip()
        
        # Check blocklist first
        for pattern in self.block_patterns:
            if pattern.search(command):
                return SafetyResult(
                    level=SafetyLevel.BLOCK,
                    reason=f"Command matches dangerous pattern: {pattern.pattern[:50]}...",
                    command=command
                )
        
        # Check graylist
        for pattern in self.gray_patterns:
            if pattern.search(command):
                return SafetyResult(
                    level=SafetyLevel.GRAY,
                    reason=f"Command requires confirmation: {pattern.pattern[:50]}...",
                    command=command
                )
        
        return SafetyResult(
            level=SafetyLevel.SAFE,
            reason="Command passed safety checks",
            command=command
        )
    
    def is_safe(self, command: str) -> bool:
        """Quick check if command is safe (no confirmation needed).
        
        Args:
            command: The command to check
            
        Returns:
            True if safe, False otherwise
        """
        result = self.check(command)
        return result.level == SafetyLevel.SAFE
    
    def is_blocked(self, command: str) -> bool:
        """Check if command is blocked.
        
        Args:
            command: The command to check
            
        Returns:
            True if blocked, False otherwise
        """
        result = self.check(command)
        return result.level == SafetyLevel.BLOCK
