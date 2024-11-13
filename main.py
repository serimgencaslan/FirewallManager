from dotenv import load_dotenv

from src.access_control_list import AccessControlList
from src.packet_filter import PacketFilter
from src.network_address_translation import NetworkAddressTranslation

load_dotenv(override=True)

def main():
    acl = AccessControlList()
    packet_filter = PacketFilter()
    nat = NetworkAddressTranslation()

    # ACL 
    acl.block_ip("192.168.1.100")
    acl.allow_ip("192.168.1.101")

    # Packet Filter
    packet_filter.block_port(22)  # block ssh
    packet_filter.allow_port(80)  # allow http

    # NAT
    nat.enable_nat("eth0")
    nat.disable_nat("eth0")

    # Backup
    print("Current Rules Backup:", acl.backup_rules())

if __name__ == "__main__":
    main()
