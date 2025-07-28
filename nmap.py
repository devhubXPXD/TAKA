try:
    import nmap
except ImportError:
    print("❌ คุณยังไม่มี nmap.exe หรือยังไม่ได้ติดตั้ง python-nmap")
    print("🔗 โปรดดาวน์โหลดได้ที่: https://nmap.org/download#windows")
    exit()

import socket
import ipaddress

def get_local_subnet():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        net = ipaddress.IPv4Network(local_ip + "/24", strict=False)
        return str(net)
    except Exception as e:
        print(f"❌ ไม่สามารถหาหมายเลข IP ได้: {e}")
        return None

def scan():
    subnet = get_local_subnet()
    if not subnet:
        return

    print(f"🔍 กำลังสแกนเครือข่าย: {subnet} ...")

    scanner = nmap.PortScanner()
    scanner.scan(hosts=subnet, arguments="-sn")

    for host in scanner.all_hosts():
        hostname = scanner[host].hostname()
        mac = scanner[host]['addresses'].get('mac', 'N/A')
        print(f"[UP] {host} ({hostname}) - MAC: {mac}")

if __name__ == "__main__":
    scan()

