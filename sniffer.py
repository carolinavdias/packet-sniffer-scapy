from scapy.all import *
import datetime

def process_packet(pkt):
    # 1. Obter o Timestamp e o Tamanho
    time_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pkt_size = len(pkt)
    
    # 2. Identificar a Interface (Passada via terminal mais tarde)
    interface = pkt.sniffed_on if pkt.sniffed_on else "N/A"

    # 3. Lógica de Identificação de Protocolos
    proto = "UNKNOWN"
    info = ""

    if ARP in pkt:
        proto = "ARP"
        # Resumo do conteúdo para ARP
        op = "request" if pkt[ARP].op == 1 else "reply"
        info = f"ARP {op} - {pkt[ARP].psrc} -> {pkt[ARP].pdst}"
        
    elif IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        if ICMP in pkt:
            proto = "ICMP"
            type_icmp = pkt[ICMP].type
            info = f"Echo Request" if type_icmp == 8 else "Echo Reply"
            info += f" ({src_ip} -> {dst_ip})"
            
        elif TCP in pkt:
            proto = "TCP"
            info = f"{src_ip}:{pkt[TCP].sport} -> {dst_ip}:{pkt[TCP].dport} [Flags: {pkt[TCP].flags}]"
            
        elif UDP in pkt:
            proto = "UDP"
            info = f"{src_ip}:{pkt[UDP].sport} -> {dst_ip}:{pkt[UDP].dport}"

    # 4. Modo LIVE: Imprimir na consola de forma formatada
    print(f"[{time_now}] | {interface} | {proto} | {pkt_size} bytes")
    if info:
        print(f"   -> Resumo: {info}")
    print("-" * 50)

def main():
    print("=== O meu Packet Sniffer (Iniciado) ===")
    print("A capturar pacotes... (Prime Ctrl+C para parar)")
    
    # Inicia a captura (sniff). 
    # prn=process_packet: chama a nossa função para cada pacote
    # store=0: não guarda pacotes na RAM para não crashar o PC
    sniff(prn=process_packet, store=0)

if __name__ == "__main__":
    main()