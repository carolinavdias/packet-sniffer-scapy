import argparse
from scapy.all import *
import datetime

def process_packet(pkt, args):
    # 1. FILTROS DE EXECUÇÃO
    # Filtro de Protocolo
    if args.protocol:
        p_lower = args.protocol.lower()
        if p_lower == "icmp" and ICMP not in pkt: return
        if p_lower == "tcp" and TCP not in pkt: return
        if p_lower == "udp" and UDP not in pkt: return
        if p_lower == "arp" and ARP not in pkt: return

    # Filtro de IP
    if args.ip:
        if IP not in pkt or (pkt[IP].src != args.ip and pkt[IP].dst != args.ip):
            return

    # Filtro de MAC
    if args.mac:
        if pkt.src != args.mac and pkt.dst != args.mac:
            return

    time_now = datetime.datetime.now().strftime("%H:%M:%S")
    proto = "UNKNOWN"
    info = ""

    # 2. PARSING
    if ARP in pkt:
        proto = "ARP"
        op = "Request" if pkt[ARP].op == 1 else "Reply"
        info = f"{op}: {pkt[ARP].psrc} -> {pkt[ARP].pdst}"
    elif IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        ttl = pkt[IP].ttl
        if ICMP in pkt:
            proto = "ICMP"
            info = f"Type {pkt[ICMP].type} (TTL:{ttl})"
        elif TCP in pkt:
            proto = "TCP"
            info = f"{src_ip}:{pkt[TCP].sport} -> {dst_ip}:{pkt[TCP].dport} [Flags: {pkt[TCP].flags}, TTL:{ttl}]"
        elif UDP in pkt:
            proto = "UDP"
            info = f"{src_ip}:{pkt[UDP].sport} -> {dst_ip}:{pkt[UDP].dport} [TTL:{ttl}]"

    summary_line = f"[{time_now}] {proto} | {len(pkt)} bytes | {info if info else pkt.summary()}"

    if args.live: print(summary_line)
    if args.log:
        with open(args.log, "a") as f:
            f.write(summary_line + "\n")

def main():
    parser = argparse.ArgumentParser(description="O meu Packet Sniffer RC")
    parser.add_argument("-i", "--interface", help="Seleciona a interface de rede a capturar")
    parser.add_argument("-p", "--protocol", help="Filtra por protocolo (arp, icmp, tcp, udp)")
    parser.add_argument("--ip", help="Filtra por endereço IP de origem ou destino")
    parser.add_argument("--mac", help="Filtra por endereço MAC")
    parser.add_argument("-l", "--log", help="Ativa modo log e define ficheiro de saída")
    parser.add_argument("--live", action="store_true", help="Ativa impressão em tempo real na consola")
    
    args = parser.parse_args()

    if not args.live and not args.log:
        print("\n[!] AVISO: Define --live ou --log para ver resultados.\n")
    
    print(f"A iniciar captura...")
    try:
        sniff(iface=args.interface, prn=lambda p: process_packet(p, args), store=0)
    except KeyboardInterrupt:
        print("\n[!] Captura terminada.")

if __name__ == "__main__":
    main()