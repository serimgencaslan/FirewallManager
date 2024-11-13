from typing import Optional

from src.firewall_base import FirewallBase
from src.firewall_manager import FirewallManager

class PacketFilter(FirewallBase):
    def apply_rule(self, rule:str) -> None:
        """
        Apply a packet filter rule to the firewall
        
        Args:
            rule (str): The packet filter rule to apply
        
        Returns:
            None
        """
        FirewallManager.run_command(rule)
        self.rules.append(rule)

    def block_port(self, port:int, protocol:Optional[str]="tcp") -> None:
        """
        Block a specific port on the firewall for a given protocol
        
        Args:
            port (int): The port number to block
            protocol (str, optional): The protocol to block (default is "tcp")
        
        Returns:
            None
        """
        rule = f"sudo iptables -A INPUT -p {protocol} --dport {port} -j DROP"
        self.apply_rule(rule)
        self.log_rule("Port Blocked", f"Blocked {protocol.upper()} port {port}")

    def allow_port(self, port:int, protocol:Optional[str]="tcp") -> None:
        """
        Allow traffic on a specific port for a given protocol
        
        Args:
            port (int): The port number to allow
            protocol (str, optional): The protocol to allow (default is "tcp")
        
        Returns:
            None
        """
        rule = f"sudo iptables -A INPUT -p {protocol} --dport {port} -j ACCEPT"
        self.apply_rule(rule)
        self.log_rule("Port Allowed", f"Allowed {protocol.upper()} port {port}")
