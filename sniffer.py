import argparse
from scapy.all import *
import datetime

# Função para processar cada pacote
def process_packet(pkt, args):
    # Filtro manual de protocolo (se o utilizador definiu um)
    if args.protocol:
        if args.protocol.lower() == "icmp" and ICMP not in pkt: return
        if args.protocol.lower() == "tcp" and TCP not in pkt: return
        if args.protocol.lower() == "udp" and UDP not in pkt: return
        if args.protocol.lower() == "arp" and ARP not in pkt: return

    time_now = datetime.datetime.now().strftime("%H:%M:%S")
    proto = "UNKNOWN"
    
    if ARP in pkt: proto = "ARP"
    elif ICMP in pkt: proto = "ICMP"
    elif TCP in pkt: proto = "TCP"
    elif UDP in pkt: proto = "UDP"

    # Modo LIVE (Consola)
    if args.live:
        print(f"[{time_now}] {proto} | {len(pkt)} bytes | {pkt.summary()}")

    # Modo LOG (Ficheiro)
    if args.log:
        with open(args.log, "a") as f:
            f.write(f"{time_now}, {proto}, {len(pkt)}, {pkt.summary()}\n")

def main():
    parser = argparse.ArgumentParser(description="O meu Packet Sniffer RC")
    parser.add_argument("-i", "--interface", help="Interface de rede (ex: eth0, wlan0)")
    parser.add_argument("-p", "--protocol", help="Filtrar por protocolo (icmp, tcp, udp, arp)")
    parser.add_argument("-l", "--log", help="Nome do ficheiro para guardar o log (.txt ou .csv)")
    parser.add_argument("--live", action="store_true", help="Ativar visualização em tempo real")
    
    args = parser.parse_args()

    # Corrigido aqui: o print tem de estar "dentro" do if (com espaços)
    if not args.live and not args.log:
        print("Aviso: Não selecionaste o modo --live nem --log. O sniffer está a trabalhar em silêncio!")
    
    print(f"A iniciar captura na interface: {args.interface if args.interface else 'Todas'}")
    
    # Inicia o sniffer
    sniff(iface=args.interface, prn=lambda p: process_packet(p, args), store=0)

if __name__ == "__main__":
    main()