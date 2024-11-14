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

    def block_port(self, port:int, protocol:Optional[str] = "tcp", src_ip:Optional[str] = None, dest_ip:Optional[str] = None) -> None:
        """
        Block a specific port on the firewall for a given protocol with optional source/destination IP
        
        Args:
            port (int): The port number to block
            protocol (str, optional): The protocol to block (default is tcp)
            src_ip (str, optional): Source IP address to block (default is None)
            dest_ip (str, optional): Destination IP address to block (default is None)
        """
        rule = f"sudo iptables -A INPUT -p {protocol} --dport {port}"
        if src_ip:
            rule += f" -s {src_ip}"
        if dest_ip:
            rule += f" -d {dest_ip}"
        rule += " -j DROP"

        self.apply_rule(rule)
        self.log_rule("Port Blocked", f"Blocked {protocol.upper()} port {port}, Source IP: {src_ip}, Destination IP: {dest_ip}")

    def allow_port(self, port:int, protocol:Optional[str] = "tcp", src_ip:Optional[str] = None, dest_ip:Optional[str] = None) -> None:
        """
        Allow traffic on a specific port for a given protocol with optional source/destination IP 
        
        Args:
            port (int): The port number to allow
            protocol (str, optional): The protocol to allow (default is tcp)
            src_ip (str, optional): Source IP address to allow (default is None)
            dest_ip (str, optional): Destination IP address to allow (default is None
        """
        rule = f"sudo iptables -A INPUT -p {protocol} --dport {port}"
        if src_ip:
            rule += f" -s {src_ip}"
        if dest_ip:
            rule += f" -d {dest_ip}"
        rule += " -j ACCEPT"
        
        self.apply_rule(rule)
        self.log_rule("Port Allowed", f"Allowed {protocol.upper()} port {port}, Source IP: {src_ip}, Destination IP: {dest_ip}")

    def block_protocol(self, protocol: str) -> None:
        """
        Block all traffic for a specific protocol ('tcp', 'udp', 'icmp' ...)
        
        Args:
            protocol (str): The protocol to block
        """
        rule = f"sudo iptables -A INPUT -p {protocol} -j DROP"
        self.apply_rule(rule)
        self.log_rule("Protocol Blocked", f"Blocked all {protocol.upper()} traffic")