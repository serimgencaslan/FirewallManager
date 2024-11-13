from abc import ABC, abstractmethod
from typing import List

from utils.utils import log_action

class FirewallBase(ABC):
    def __init__(self):
        self.rules = [] # List of firewall rules

    @abstractmethod
    def apply_rule(self, rule:str) -> None:
        """
        Apply a firewall rule
        
        Args:
            rule (str): The firewall rule to apply
        
        Returns:
            None
        """
        pass

    def backup_rules(self) -> List[str]:
        """
        Backup the current firewall rules
                
        Returns:
            List[str]: A list of firewall rules
        """
        log_action("Backup", "Firewall rules backed up")
        return self.rules

    def restore_rules(self, rules:List[str]) -> None:
        """
        Restore the firewall rules from a backup
        
        Args:
            rules (List[str]): A list of firewall rules to restore
        
        Returns:
            None
        """
        self.rules = rules
        log_action("Restore", "Firewall rules restored")

    def log_rule(self, action:str, details:str) -> None:
        """
        Log an action performed on the firewall rules
        
        Args:
            action (str): The action being logged (e.g. : 'IP BLocked', 'NAT Enabled')
            details (str): Additional details about the action
        
        Returns:
            None
        """
        log_action(action, details)
