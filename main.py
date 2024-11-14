from dotenv import load_dotenv

from src.access_control_list import AccessControlList
from src.packet_filter import PacketFilter
from src.network_address_translation import NetworkAddressTranslation

load_dotenv(override=True)

def main():
    acl = AccessControlList()
    packet_filter = PacketFilter()
    nat = NetworkAddressTranslation()

    # add ACL rules
    acl.add_acl_rule(ip="192.168.1.100", action="BLOCK")  # IP engelle
    acl.add_acl_rule(ip="192.168.1.101", action="ALLOW")  # IP izin ver
    acl.add_acl_rule(ip="192.168.1.50", port=80, protocol="tcp", action="BLOCK")  # TCP 80 portunu engelle
    acl.add_acl_rule(ip="10.0.0.5", port=22, protocol="tcp", action="ALLOW")  # TCP 22 portuna izin ver

    # list ACL rules
    print("Mevcut ACL rules:", acl.list_acl_rules())
    
    # remove ACL rule
    acl.remove_acl_rule(ip="192.168.1.101", protocol="tcp")
    
    print("Güncellenmiş ACL rules:", acl.list_acl_rules())
    
    # Packet Filter
    packet_filter.block_port(22)  # SSH engelle
    packet_filter.allow_port(80)  # HTTP izin ver
    # Port bazlı engelleme ve izin verme
    packet_filter.block_port(22, protocol="tcp")  # SSH engelle
    packet_filter.allow_port(80, protocol="tcp")  # HTTP izin ver
    packet_filter.allow_port(443, protocol="tcp") # HTTPS izin ver

    # Kaynak/Destinasyon IP bazlı engelleme
    packet_filter.block_port(3306, protocol="tcp", src_ip="192.168.1.100")  # MySQL erişimini engelle

    # Belirli bir protokolü tamamen engelle
    packet_filter.block_protocol("icmp")  # Ping trafiğini engelle

    # NAT
    nat.enable_nat("eth0")
    nat.disable_nat("eth0")

    # Backup
    print("Current Rules Backup:", acl.backup_rules())

if __name__ == "__main__":
    main()
