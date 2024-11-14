import json
import os
from typing import List

from src.firewall_base import FirewallBase
from src.firewall_manager import FirewallManager

class AccessControlList(FirewallBase):
    def __init__(self) -> None:
        super().__init__()
        self.whitelist_filename = str(os.getenv("WHITELIST_FILE_PATH"))
        self.blacklist_filename = str(os.getenv("BLACKLIST_FILE_PATH"))
        self.whitelist = self.load_ip_list(self.whitelist_filename)
        self.blacklist = self.load_ip_list(self.blacklist_filename)

    def load_ip_list(self, filename:str) -> List[str]:
        """ load IP list from a json file

        Args:
            filename (str): file name of the json file which includes IP list

        Returns:
            List[str]: list of IP addresses
        """
        try:
            with open(filename, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            return []

    def save_ip_list(self, filename: str, ip_list: List[str]) -> None:
        """ save IP list into a json file

        Args:
            filename (str): filename of the json file which will be saved
            ip_list (List[str]): list of IP addresses which will be saved
        """
        with open(filename, 'w') as file:
            json.dump(ip_list, file)

    def apply_rule(self, rule:str) -> None:
        """ apply the rule

        Args:
            rule (str): the rule wihch will be applied.
        """
        FirewallManager.run_command(rule)
        self.rules.append(rule)

    def block_ip(self, ip_address:str) -> None:
        """ block the ip address 

        Args:
            ip_address (str): the IP address which will be blocked
        """
        rule = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
        self.apply_rule(rule)
        if ip_address not in self.blacklist:
            self.blacklist.append(ip_address)
            self.save_ip_list(self.blacklist_filename, self.blacklist)
        self.log_rule("IP Blocked", f"Blocked IP: {ip_address}")

    def allow_ip(self, ip_address:str) -> None:
        """ allow the ip address 

        Args:
            ip_address (str): the IP address which will be allowed
        """
        rule = f"sudo iptables -A INPUT -s {ip_address} -j ACCEPT"
        self.apply_rule(rule)
        if ip_address not in self.whitelist:
            self.whitelist.append(ip_address)
            self.save_ip_list(self.whitelist_filename, self.whitelist)
        self.log_rule("IP Allowed", f"Allowed IP: {ip_address}")