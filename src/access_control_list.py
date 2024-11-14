import json
import os
from typing import List, Dict, Optional

from src.firewall_base import FirewallBase
from src.firewall_manager import FirewallManager

class AccessControlList(FirewallBase):
    def __init__(self) -> None:
        super().__init__()
        self.whitelist_filename = str(os.getenv("WHITELIST_FILE_PATH", "whitelist.json"))
        self.blacklist_filename = str(os.getenv("BLACKLIST_FILE_PATH", "blacklist.json"))
        self.rules_filename = str(os.getenv("RULES_FILE_PATH", "acl_rules.json"))

        # Load IP lists and ACL rules
        self.whitelist = self.load_ip_list(self.whitelist_filename)
        self.blacklist = self.load_ip_list(self.blacklist_filename)
        self.acl_rules = self.load_rules(self.rules_filename)

    def load_ip_list(self, filename: str) -> List[str]:
        try:
            with open(filename, 'r') as file:
                return json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def save_ip_list(self, filename: str, ip_list: List[str]) -> None:
        with open(filename, 'w') as file:
            json.dump(ip_list, file)

    def load_rules(self, filename: str) -> List[Dict[str, Optional[str]]]:
        try:
            with open(filename, 'r') as file:
                return json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def save_rules(self, filename: str, rules: List[Dict[str, Optional[str]]]) -> None:
        with open(filename, 'w') as file:
            json.dump(rules, file)

    def apply_rule(self, rule: str) -> None:
        FirewallManager.run_command(rule)
        self.rules.append(rule)

    def update_whitelist(self, ip: str) -> None:
        if ip not in self.whitelist:
            self.whitelist.append(ip)
            self.save_ip_list(self.whitelist_filename, self.whitelist)
            self.log_rule("Whitelist Updated", f"Added {ip} to whitelist")

    def update_blacklist(self, ip: str) -> None:
        if ip not in self.blacklist:
            self.blacklist.append(ip)
            self.save_ip_list(self.blacklist_filename, self.blacklist)
            self.log_rule("Blacklist Updated", f"Added {ip} to blacklist")

    def add_acl_rule(self, ip: str, port: Optional[int] = None, protocol: Optional[str] = None, action: str = "ALLOW") -> None:
        if action.upper() not in ["ALLOW", "BLOCK"]:
            raise ValueError("Action must be 'ALLOW' or 'BLOCK'")

        rule = f"sudo iptables -A INPUT -s {ip}"
        if protocol:
            rule += f" -p {protocol.lower()}"
        if port:
            rule += f" --dport {port}"
        rule += f" -j {'ACCEPT' if action.upper() == 'ALLOW' else 'DROP'}"

        self.apply_rule(rule)
        
        if action.upper() == "ALLOW":
            self.update_whitelist(ip)
        else:
            self.update_blacklist(ip)

        self.acl_rules.append({"ip": ip, "port": port, "protocol": protocol, "action": action})
        self.save_rules(self.rules_filename, self.acl_rules)
        self.log_rule("ACL Rule Added", f"Rule: {action} IP: {ip}, Port: {port}, Protocol: {protocol}")


    def remove_acl_rule(self, ip: str, port: Optional[int] = None, protocol: Optional[str] = None) -> None:
        """
        Remove a specific ACL rule from both the internal list and iptables.

        Args:
            ip (str): The IP address of the rule to remove
            port (Optional[int]): The port number of the rule to remove (optional)
            protocol (Optional[str]): The protocol of the rule to remove ("tcp" or "udp", optional)
        """
        # Remove the rule from the internal ACL list
        self.acl_rules = [
            rule for rule in self.acl_rules
            if not (rule['ip'] == ip and rule.get('port') == port and rule.get('protocol') == protocol)
        ]
        self.save_rules(self.rules_filename, self.acl_rules)
        self.log_rule("ACL Rule Removed", f"Removed rule for IP: {ip}, Port: {port}, Protocol: {protocol}")

        # Build the iptables delete command
        rule = f"sudo iptables -D INPUT -s {ip}"
        if protocol:
            rule += f" -p {protocol.lower()}"
        if port:
            rule += f" --dport {port}"
        
        # Determine if the original rule was ACCEPT or DROP
        if ip in self.whitelist:
            rule += " -j ACCEPT"
        else:
            rule += " -j DROP"

        # Check if the rule exists before attempting to delete it
        try:
            # Komutları kontrol etmek için doğrudan subprocess kullanıyoruz
            list_command = "sudo iptables -S INPUT"
            import subprocess

            result = subprocess.run(list_command, shell=True, capture_output=True, text=True)

            # Çıktıda kuralın olup olmadığını kontrol ediyoruz
            if rule in result.stdout:
                FirewallManager.run_command(rule)
            else:
                self.log_rule("Rule Not Found", f"No matching iptables rule found for: {rule}")
        except Exception as e:
            self.log_rule("Command Failed", f"Error: {str(e)}")



    def is_ip_whitelisted(self, ip:str) -> bool:
        """Check if an IP is in the whitelist"""
        return ip in self.whitelist

    def list_acl_rules(self) -> List[Dict[str, Optional[str]]]:
        return self.acl_rules
