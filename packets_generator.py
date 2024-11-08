import psutil
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP

packets_collection = dict()

def get_network_interfaces():
    interfaces = {}

    print("Найденные сетевые интерфейсы:\n> ")

    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == psutil.AF_LINK:
                interfaces[iface] = addrs
                break

    return interfaces

def choose_interface(interfaces):
    print("Сетевые интерфейсы:")

    for idx, iface in enumerate(interfaces.keys()):
        print(f"\t{idx}: {iface}")

    idx = int(input("Введите номер интерфейса:\n> "))

    return list(interfaces.keys())[idx]

def getMAC(ip, interface):
    conf.iface = interface  # Устанавливаем интерфейс
    arp_request = ARP(pdst=ip)
    arp_response = sr1(arp_request, timeout=7, verbose=False)
    return arp_response.hwsrc if arp_response else None

def makeEthernet(src_ip, dst_ip, interface):
    src_mac = get_if_hwaddr(interface) if src_ip == "0" else getMAC(src_ip, interface)
    dst_mac = getMAC("192.168.0.1", interface)
    
    if src_mac is not None:
        print(f"MAC отправителя: {src_mac}")

    if dst_mac is not None:
        print(f"MAC получателя: {dst_mac}")

    if dst_mac is None:
        print(f"MAC-адрес для {dst_ip} не найден.")
        return None
    elif src_mac is None:
        print(f"MAC-адрес для {src_ip} не найден.")
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
        print("Выберите какие параметры пакета хотите изменить:")
        print("\t0 - далее\n\t1 - ttl\n\t2 - proto\n\t3 - id\n\t4 - frag\n\t5 - flags\n\t6 - tos\n\t7 - checksum\n\t8 - options\n\t9 - len\n\t10 - version")

        choice = input("> ")

        if choice == "0":
            break
        
        elif choice == "1":
            param = input("Введите значение:\n> ")
            extra_args["ttl"] = int(param)

        elif choice == "2":
            param = input("Введите значение:\n> ")
            extra_args["proto"] = int(param)

        elif choice == "3":
            param = input("Введите значение:\n> ")
            extra_args["id"] = int(param)

        elif choice == "4":
            param = input("Введите значение:\n> ")
            extra_args["frag"] = int(param)

        elif choice == "5":
            param = input("Введите значение:\n> ")
            extra_args["flags"] = int(param)

        elif choice == "6":
            param = input("Введите значение:\n> ")
            extra_args["tos"] = int(param)
            
        elif choice == "7":
            param = input("Введите значение:\n> ")
            extra_args["checksum"] = int(param)
            
        elif choice == "8":
            param = input("Введите значение:\n> ")
            extra_args["options"] = int(param)

        elif choice == "9":
            param = input("Введите значение:\n> ")
            extra_args["len"] = int(param)

        elif choice == "10":
            param = input("Введите значение:\n> ")
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
        print("Выберите какие параметры пакета хотите изменить:")
        print("\t0 - далее\n\t1 - seq\n\t2 - ack\n\t3 - flags\n\t4 - window\n\t5 - chksum\n\t6 - urgptr\n\t7 - options\n\t8 - dataofs\n")

        choice = input("> ")

        if choice == "0":
            break
        
        elif choice == "1":
            param = input("Введите значение (число):\n> ")
            extra_args["seq"] = int(param)

        elif choice == "2":
            param = input("Введите значение (число):\n> ")
            extra_args["ack"] = int(param)

        elif choice == "3":
            param = input("Введите значение (например, A или SA или P...):\n> ")
            extra_args["flags"] = param

        elif choice == "4":
            param = input("Введите значение (число):\n> ")
            extra_args["window"] = int(param)

        elif choice == "5":
            param = input("Введите значение (число):\n> ")
            extra_args["chksum"] = int(param)

        elif choice == "6":
            param = input("Введите значение (число):\n> ")
            extra_args["urgptr"] = int(param)
            
        elif choice == "7":
            param = input("Введите значение (в виде param value; param value;...):\n> ")
            extra_args["options"] = parseOptionsTCP(param)
        
        elif choice == "8":
            param = input("Введите значение (число):\n> ")
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
        print("Выберите какие параметры пакета хотите изменить:")
        print("\t0 - далее\n\t1 - len\n\t2 - chksum\n")

        choice = input("> ")

        if choice == "0":
            break
        
        elif choice == "1":
            param = input("Введите значение (число):\n> ")
            extra_args["len"] = int(param)

        elif choice == "2":
            param = input("Введите значение (число):\n> ")
            extra_args["chksum"] = int(param)

        else:
            print("Нету такого!")
    
    return extra_args


def makeICMP(type="echo-request", **kwargs):
    icmp_packet = ICMP(type=8) if type == "echo-request" else ICMP(type=0)

    for key, value in kwargs.items():
        setattr(icmp_packet, key, value)

    return icmp_packet

# TODO
def getICMPAttrs() -> dict:
    ...


def sendPacket():
    if len(packets_collection) == 0:
        print("У вас нет сформированных пакетов!\n")
        return
    
    print("Ваши пакеты:")

    for idx, packet in enumerate(packets_collection):
        print(f"\t{packet}")
    
    print("Введите имена пакетов, которые хотите отправить (например: 5 1 3):")
    packets = input("> ").split(" ")

    for packet in packets:
        try:
            sendp(packets_collection[packet][0], iface=packets_collection[packet][1], verbose=False)
            del packets_collection[packet]
            print("Пакет отправлен")
        except Exception as e:
            print(f"Ошибка: {e}")

def generatePacket():
    interfaces = get_network_interfaces()
    interface = choose_interface(interfaces)
    
    src_ip = input("Введите исходный IP (0 - авто [192.168.0.104]):\n> ")
    dst_ip = input("Введите IP назначения (0 - ibks [195.209.230.198]):\n> ")

    if dst_ip == "0":
        dst_ip = "195.209.230.198"

    print("\n")
    eth_packet = makeEthernet(src_ip, dst_ip, interface)
    
    if src_ip == "0":
        src_ip = "192.168.0.104"
    
    if eth_packet is None:
        print("Ошибка при создании Ethernet пакета.")
        return
    
    print("\n")
    pkt_type = input("Введите тип пакета:\n\t1 - IP\n\t2 - TCP\n\t3 - UDP\n\t4 - ICMP\n> ").strip().upper()
    
    # IP
    if pkt_type == "1":
        ip_packet = makeIP(src_ip, dst_ip, **getIPAttrs())
        packet = eth_packet / ip_packet
    
    # TCP
    elif pkt_type == "2":
        src_port = int(input("Введите исходный порт:\n> "))
        dst_port = int(input("Введите целевой порт:\n> "))
        tcp_packet = makeTCP(src_port, dst_port, **getTCPAttrs())

        print("\nIP менять надо?\n\t0 - да\n\t1 - нет")
        choice = input("> ")

        print("\nPayload нужно добавить?\n\t0 - да\n\t1 - нет")
        pl_choice = input("> ")

        if pl_choice == "0":
            payload = input("Введите данные:\n> ")

        if choice == "0":
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
        src_port = int(input("Введите исходный порт:\n> "))
        dst_port = int(input("Введите целевой порт:\n> "))
        udp_packet = makeUDP(src_port, dst_port, **getUDPAttrs())

        print("\nIP менять надо?\n\t0 - да\n\t1 - нет")
        choice = input("> ")

        print("\nPayload нужно добавить?\n\t0 - да\n\t1 - нет")
        pl_choice = input("> ")

        if pl_choice == "0":
            payload = input("Введите данные:\n> ")

        if choice == "0":
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
        icmp_type = input("Введите тип ICMP:\n\t1 - echo-request\n\t2 - echo-reply:\n> ").strip().lower()

        if icmp_type not in ["1", "2"]:
            print("Нет такого!")
            exit(-1)

        icmp_packet = makeICMP(type=icmp_type)

        print("\nIP менять надо?\n\t0 - да\n\t1 - нет")
        choice = input("> ")

        if choice == "0":
            packet = eth_packet / makeIP(src_ip, dst_ip, **getIPAttrs()) / icmp_packet
        else:
            packet = eth_packet / makeIP(src_ip, dst_ip) / icmp_packet
    
    else:
        print("Нет такого!")
        return
    
    packet_name = input("Введите имя для этого пакета:\n> ")

    packets_collection[packet_name] = [packet, interface]
    print("Пакет успешно сформирован\n")

def printMenu():
    print("Выберите че хотите сделать:\n\t1 - сформировать новый пакет\n\t2 - отправить пакет/последовательность пакетов\n\t3 - выход\n")

if __name__ == "__main__":
    print("Packets generator v1.0.1 alpha by @milky_VVay\n")

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
    
