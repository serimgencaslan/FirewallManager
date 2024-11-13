from src.firewall_base import FirewallBase
from src.firewall_manager import FirewallManager

class NetworkAddressTranslation(FirewallBase):
    def apply_rule(self, rule:str) -> None:
        """
        Apply a NAT rule to the firewall
        
        Args:
            rule (str): The NAT rule to apply
        
        Returns:
            None
        """
        FirewallManager.run_command(rule)
        self.rules.append(rule)

    def enable_nat(self, interface:str) -> None:
        """
        Enable NAT on the specified interface
        
        Args:
            interface (str): The network interface to apply NAT on (e.g. : 'eth0', 'eth1)
        
        Returns:
            None
        """ 
        rule = f"sudo iptables -t nat -A POSTROUTING -o {interface} -j MASQUERADE"
        self.apply_rule(rule)
        self.log_rule("NAT Enabled", f"NAT enabled on interface {interface}")

    def disable_nat(self, interface:str) -> None:
        """
        Disable NAT on the specified interface
        
        Args:
            interface (str): The network interface to remove NAT from ('eth0', 'eth1')
        
        Returns:
            None
        """
        rule = f"sudo iptables -t nat -D POSTROUTING -o {interface} -j MASQUERADE"
        self.apply_rule(rule)
        self.log_rule("NAT Disabled", f"NAT disabled on interface {interface}")
