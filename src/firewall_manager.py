import subprocess
from utils.utils import log_action

class FirewallManager:
    @staticmethod
    def run_command(command):
        try:
            subprocess.run(command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            log_action("Command Failed", str(e))
