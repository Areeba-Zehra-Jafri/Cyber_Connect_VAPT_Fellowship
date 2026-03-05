import pyshark

PCAP_FILE = "capture.pcapng"
TSHARK_PATH = r"D:\Wireshark\tshark.exe"

def extract_dns_traffic(pcap_path):
    print(f"Opening file: {pcap_path}")
    print(f"{'='*45}")
    print(f"{'Source IP':<20} {'Queried Domain'}")
    print(f"{'='*45}")

    # Open the pcap and filter for DNS traffic only
    capture = pyshark.FileCapture(pcap_path, display_filter="dns", tshark_path=TSHARK_PATH)

    for packet in capture:
        try:
            # Only process DNS query packets (not responses)
            if hasattr(packet, 'dns') and packet.dns.flags_response == '0':
                source_ip = packet.ip.src
                queried_domain = packet.dns.qry_name

                print(f"{source_ip:<20} {queried_domain}")

        except AttributeError:
            # Skip packets missing expected fields
            continue

    capture.close()
    print(f"{'='*45}")
    print("Done.")

if __name__ == "__main__":
    extract_dns_traffic(PCAP_FILE)
