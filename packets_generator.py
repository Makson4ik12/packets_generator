import psutil
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP

packets_collection = dict()

def getNetworkInterfaces() -> dict:
    interfaces = {}
    
    for iface, addrs in psutil.net_if_addrs().items():
        iface_info = {"name": iface, "ip": None}
        
        for addr in addrs:
            if addr.family == socket.AF_INET:
                iface_info["ip"] = addr.address

        interfaces[iface] = iface_info
    
    return interfaces

def chooseInterface(interfaces):
    print("\nСетевые интерфейсы:")

    for idx, iface in enumerate(interfaces.values()):
        print(f"\t[{idx}] {iface['name']} ({iface['ip']})")

    idx = int(input("\nВведите номер интерфейса:\n> "))
    selected_iface = list(interfaces.values())[idx]

    return selected_iface["ip"], selected_iface["name"]

def getMAC(ip, interface):
    conf.iface = interface
    arp_request = ARP(pdst=ip)
    arp_response = sr1(arp_request, timeout=3, verbose=False)
    return arp_response.hwsrc if arp_response else None

def makeEthernet(src_ip: str, interface):
    src_mac = getMAC(src_ip, interface)

    if src_mac == None:
        src_mac = get_if_hwaddr(interface)

    tmp = src_ip.split(".")
    tmp.pop()
    tmp.append("1")
    gateway_ip = '.'.join(tmp)

    print(f"\n[+] Адрес шлюза: {gateway_ip}")

    dst_mac = getMAC(gateway_ip, interface)
    
    if src_mac is not None:
        print(f"\n[+] MAC отправителя: {src_mac}")

    if dst_mac is not None:
        print(f"\n[+] MAC получателя: {dst_mac}")

    if dst_mac is None:
        print(f"\n[-] MAC-адрес для {gateway_ip} не найден.")
        return None
    elif src_mac is None:
        print(f"\n[-] MAC-адрес для {src_ip} не найден.")
        return None

    return Ether(src=src_mac, dst=dst_mac)


def makeIP(src_ip, dst_ip, **kwargs) -> Packet:
    ip_packet = IP(src=src_ip, dst=dst_ip)

    for key, value in kwargs.items():
        setattr(ip_packet, key, value)

    return ip_packet

def getIPAttrs() -> dict:
    extra_args = dict()

    while True:
        print("\nВыберите какие параметры пакета хотите изменить:")
        print("\t[0] далее\n\t[1] ttl\n\t[2] proto\n\t[3] id\n\t[4] frag\n\t[5] flags\n\t[6] tos\n\t[7] checksum\n\t[8] options\n\t[9] len\n\t[10] version")

        choice = input("> ")

        if choice == "0":
            break
        
        elif choice == "1":
            param = input("\nВведите значение:\n> ")
            extra_args["ttl"] = int(param)

        elif choice == "2":
            param = input("\nВведите значение:\n> ")
            extra_args["proto"] = int(param)

        elif choice == "3":
            param = input("\nВведите значение:\n> ")
            extra_args["id"] = int(param)

        elif choice == "4":
            param = input("\nВведите значение:\n> ")
            extra_args["frag"] = int(param)

        elif choice == "5":
            param = input("\nВведите значение:\n> ")
            extra_args["flags"] = int(param)

        elif choice == "6":
            param = input("\nВведите значение:\n> ")
            extra_args["tos"] = int(param)
            
        elif choice == "7":
            param = input("\nВведите значение:\n> ")
            extra_args["checksum"] = int(param)
            
        elif choice == "8":
            param = input("\nВведите значение:\n> ")
            extra_args["options"] = int(param)

        elif choice == "9":
            param = input("\nВведите значение:\n> ")
            extra_args["len"] = int(param)

        elif choice == "10":
            param = input("\nВведите значение:\n> ")
            extra_args["version"] = int(param)

        else:
            print("Нету такого!")
    
    return extra_args


def makeTCP(src_port, dst_port, **kwargs) -> Packet:
    tcp_packet = TCP(sport=src_port, dport=dst_port)

    for key, value in kwargs.items():
        setattr(tcp_packet, key, value)

    return tcp_packet

def parseOptionsTCP(option_string) -> list:
    options = option_string.split(";")
    parsed_options = []
    
    for option in options:
        option = option.strip()
        
        if not option:
            continue
        
        param, value = option.split()
        parsed_options.append((param, int(value)))
    
    return parsed_options

def getTCPAttrs() -> dict:
    extra_args = dict()

    while True:
        print("\nВыберите какие параметры пакета хотите изменить:")
        print("\t[0] далее\n\t[1] seq\n\t[2] ack\n\t[3] flags\n\t[4] window\n\t[5] chksum\n\t[6] urgptr\n\t[7] options\n\t[8] dataofs\n")

        choice = input("> ")

        if choice == "0":
            break
        
        elif choice == "1":
            param = input("\nВведите значение (число):\n> ")
            extra_args["seq"] = int(param)

        elif choice == "2":
            param = input("\nВведите значение (число):\n> ")
            extra_args["ack"] = int(param)

        elif choice == "3":
            param = input("\nВведите значение (например, A или SA или P...):\n> ")
            extra_args["flags"] = param

        elif choice == "4":
            param = input("\nВведите значение (число):\n> ")
            extra_args["window"] = int(param)

        elif choice == "5":
            param = input("\nВведите значение (число):\n> ")
            extra_args["chksum"] = int(param)

        elif choice == "6":
            param = input("\nВведите значение (число):\n> ")
            extra_args["urgptr"] = int(param)
            
        elif choice == "7":
            param = input("\nВведите значение (в виде param value; param value;...):\n> ")
            extra_args["options"] = parseOptionsTCP(param)
        
        elif choice == "8":
            param = input("\nВведите значение (число):\n> ")
            extra_args["dataofs"] = int(param)

        else:
            print("Нету такого!")
    
    return extra_args


def makeUDP(src_port, dst_port, **kwargs) -> Packet:
    udp_packet = UDP(sport=src_port, dport=dst_port)

    for key, value in kwargs.items():
        setattr(udp_packet, key, value)

    return udp_packet

def getUDPAttrs() -> dict:
    extra_args = dict()

    while True:
        print("\nВыберите какие параметры пакета хотите изменить:")
        print("\t[0] далее\n\t[1] len\n\t[2] chksum\n")

        choice = input("> ")

        if choice == "0":
            break
        
        elif choice == "1":
            param = input("\nВведите значение (число):\n> ")
            extra_args["len"] = int(param)

        elif choice == "2":
            param = input("\nВведите значение (число):\n> ")
            extra_args["chksum"] = int(param)

        else:
            print("Нету такого!")
    
    return extra_args


def makeICMP(type="echo-request", **kwargs):
    icmp_packet = ICMP(type=8) if type == "echo-request" else ICMP(type=0)

    for key, value in kwargs.items():
        setattr(icmp_packet, key, value)

    return icmp_packet

def getICMPAttrs() -> dict:
    extra_args = dict()

    while True:
        print("\nВыберите какие параметры пакета хотите изменить:")
        print("\t[0] далее\n\t[1] code\n\t[2] id\n\t[3] seq\n\t[4] chksum\n")

        choice = input("> ")

        if choice == "0":
            break
        
        elif choice == "1":
            param = input("\nВведите значение (число):\n> ")
            extra_args["code"] = int(param)

        elif choice == "2":
            param = input("\nВведите значение (число):\n> ")
            extra_args["id"] = int(param)

        elif choice == "3":
            param = input("\nВведите значение (число):\n> ")
            extra_args["seq"] = int(param)

        elif choice == "4":
            param = input("\nВведите значение (число):\n> ")
            extra_args["chksum"] = int(param)

        else:
            print("Нету такого!")
    
    return extra_args

def sendPacket():
    if len(packets_collection) == 0:
        print("\nУ вас нет сформированных пакетов!\n")
        return
    
    print("\nВаши пакеты:")

    for idx, packet in enumerate(packets_collection):
        print(f"\t{packet}")
    
    print("\nВведите имена пакетов, которые хотите отправить (например: p1 p3 p7):")
    packets = input("> ").split(" ")

    for packet in packets:
        try:
            sendp(packets_collection[packet][0], iface=packets_collection[packet][1], verbose=False)
            del packets_collection[packet]
            print(f"\n[+] Пакет <{packet}> отправлен")
        except Exception as e:
            print(f"\n[-] Ошибка: {e}")

def generatePacket():
    interfaces = getNetworkInterfaces()
    default_src_ip, interface = chooseInterface(interfaces)
    
    src_ip = input(f"\nВведите исходный IP (0 - авто [{default_src_ip}]):\n> ")
    dst_ip = input("\nВведите IP назначения (0 - google.com [142.251.33.110]):\n> ")

    if src_ip == "0":
        print(f"\n[+] Установлен дефолтный IP источника: {default_src_ip}")
        src_ip = default_src_ip

    if dst_ip == "0":
        print(f"\n[+] Установлен дефолтный IP назначения: 142.251.33.110")
        dst_ip = "142.251.33.110"

    eth_packet = makeEthernet(src_ip, interface)
    
    if eth_packet is None:
        print("Ошибка при создании Ethernet пакета.")
        return
    
    pkt_type = input("\nВведите тип пакета:\n\t[1] IP\n\t[2] TCP\n\t[3] UDP\n\t[4] ICMP\n> ").strip().upper()
    
    # IP
    if pkt_type == "1":
        ip_packet = makeIP(src_ip, dst_ip, **getIPAttrs())
        packet = eth_packet / ip_packet
    
    # TCP
    elif pkt_type == "2":
        src_port = int(input("\nВведите исходный порт:\n> "))
        dst_port = int(input("\nВведите целевой порт:\n> "))
        tcp_packet = makeTCP(src_port, dst_port, **getTCPAttrs())

        print("\nIP менять надо?\n\t[0] нет\n\t[1] да")
        choice = input("> ")

        print("\nPayload нужно добавить?\n\t[0] да\n\t[1] нет")
        pl_choice = input("> ")

        if pl_choice == "0":
            payload = input("\nВведите данные:\n> ")

        if choice == "1":
            if pl_choice == "0":
                packet = eth_packet / makeIP(src_ip, dst_ip, **getIPAttrs()) / tcp_packet / payload
            else:
                packet = eth_packet / makeIP(src_ip, dst_ip, **getIPAttrs()) / tcp_packet
        else:
            if pl_choice == "0":
                packet = eth_packet / makeIP(src_ip, dst_ip) / tcp_packet / payload
            else:
                packet = eth_packet / makeIP(src_ip, dst_ip) / tcp_packet
    
    # UDP
    elif pkt_type == "3":
        src_port = int(input("\nВведите исходный порт:\n> "))
        dst_port = int(input("\nВведите целевой порт:\n> "))
        udp_packet = makeUDP(src_port, dst_port, **getUDPAttrs())

        print("\nIP менять надо?\n\t[0] нет\n\t[1] да")
        choice = input("> ")

        print("\nPayload нужно добавить?\n\t[0] да\n\t[1] нет")
        pl_choice = input("> ")

        if pl_choice == "0":
            payload = input("\nВведите данные:\n> ")

        if choice == "1":
            if pl_choice == "0":
                packet = eth_packet / makeIP(src_ip, dst_ip, **getIPAttrs()) / udp_packet / payload
            else:
                packet = eth_packet / makeIP(src_ip, dst_ip, **getIPAttrs()) / udp_packet
        else:
            if pl_choice == "0":
                packet = eth_packet / makeIP(src_ip, dst_ip) / udp_packet / payload
            else:
                packet = eth_packet / makeIP(src_ip, dst_ip) / udp_packet
    
    # ICMP
    elif pkt_type == "4":
        icmp_type = input("\nВведите тип ICMP:\n\t[1] echo-request\n\t[2] echo-reply\n> ").strip().lower()

        if icmp_type not in ["1", "2"]:
            print("\nНет такого!")
            return
        elif icmp_type == "1":
            icmp_type = "echo-request"
        else:
            icmp_type = "echo-reply"

        icmp_packet = makeICMP(type=icmp_type, **getICMPAttrs())

        print("\nIP менять надо?\n\t[0] нет\n\t[1] да")
        choice = input("> ")
        
        print("\nPayload нужно добавить?\n\t[0] да\n\t[1] нет")
        pl_choice = input("> ")

        if pl_choice == "0":
            payload = input("\nВведите данные:\n> ")

        if choice == "1":
            if pl_choice == "0":
                packet = eth_packet / makeIP(src_ip, dst_ip, **getIPAttrs()) / icmp_packet / payload
            else:
                packet = eth_packet / makeIP(src_ip, dst_ip, **getIPAttrs()) / icmp_packet
        else:
            if pl_choice == "0":
                packet = eth_packet / makeIP(src_ip, dst_ip) / icmp_packet / payload
            else:
                packet = eth_packet / makeIP(src_ip, dst_ip) / icmp_packet
    
    else:
        print("\nНет такого!")
        return
    
    packet_name = input("\nВведите имя для этого пакета:\n> ")

    packets_collection[packet_name] = [packet, interface]
    print("\nПакет успешно сформирован\n")

def printMenu():
    print("\nВыберите че хотите сделать:\n\t[1] Сформировать новый пакет\n\t[2] Отправить пакет/последовательность пакетов\n\t[3] Выход\n")

if __name__ == "__main__":
    print("Packets generator v1.0 alpha by @milky_VVay")

    while True:
        printMenu()
        option = input("> ")

        if option == "1":
            generatePacket()
        elif option == "2":
            sendPacket()
        elif option == "3":
            print("Гудбай")
            exit()
        else:
            print("Нет такого.")
    
