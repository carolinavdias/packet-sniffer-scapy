import argparse
from scapy.all import *
import datetime

# Função para processar cada pacote (A Unidade de Análise)
def process_packet(pkt, args):
    # 1. Filtro manual de protocolo
    if args.protocol:
        p_lower = args.protocol.lower()
        if p_lower == "icmp" and ICMP not in pkt: return
        if p_lower == "tcp" and TCP not in pkt: return
        if p_lower == "udp" and UDP not in pkt: return
        if p_lower == "arp" and ARP not in pkt: return

    time_now = datetime.datetime.now().strftime("%H:%M:%S")
    proto = "UNKNOWN"
    info = ""

    # 2. Parsing de Protocolos (Extração de metadados)
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
            icmp_type = pkt[ICMP].type
            type_desc = "Echo Request" if icmp_type == 8 else "Echo Reply" if icmp_type == 0 else f"Type {icmp_type}"
            info = f"{type_desc} (TTL:{ttl})"
            
        elif TCP in pkt:
            proto = "TCP"
            # Extração de Portas e Flags (S=SYN, A=ACK, etc.)
            flags = pkt[TCP].flags
            info = f"{src_ip}:{pkt[TCP].sport} -> {dst_ip}:{pkt[TCP].dport} [Flags: {flags}, TTL:{ttl}]"
            
        elif UDP in pkt:
            proto = "UDP"
            info = f"{src_ip}:{pkt[UDP].sport} -> {dst_ip}:{pkt[UDP].dport} [TTL:{ttl}]"

    # 3. Formatação do Output
    summary_line = f"[{time_now}] {proto} | {len(pkt)} bytes | {info if info else pkt.summary()}"

    # Modo LIVE (Consola)
    if args.live:
        print(summary_line)

    # Modo LOG (Ficheiro)
    if args.log:
        with open(args.log, "a") as f:
            f.write(summary_line + "\n")

def main():
    parser = argparse.ArgumentParser(description="O meu Packet Sniffer RC")
    parser.add_argument("-i", "--interface", help="Interface de rede (ex: eth0, wlan0)")
    parser.add_argument("-p", "--protocol", help="Filtrar por protocolo (icmp, tcp, udp, arp)")
    parser.add_argument("-l", "--log", help="Nome do ficheiro para guardar o log (.txt ou .csv)")
    parser.add_argument("--live", action="store_true", help="Ativar visualização em tempo real")
    
    args = parser.parse_args()

    # Aviso de modo silencioso
    if not args.live and not args.log:
        print("\n[!] AVISO: O sniffer está a trabalhar em silêncio (sem --live ou --log).\n")
    
    print(f"A iniciar captura na interface: {args.interface if args.interface else 'Todas'}")
    
    # Inicia o sniffer (O Motor de Captura)
    try:
        sniff(iface=args.interface, prn=lambda p: process_packet(p, args), store=0)
    except KeyboardInterrupt:
        print("\n[!] Captura terminada pelo utilizador.")

if __name__ == "__main__":
    main()