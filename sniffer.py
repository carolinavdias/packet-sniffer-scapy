import argparse
from scapy.all import *
import datetime

#OPCIONAL 1: estatísticas finais ツ
#contadores globais inicializados a zero
stats = {
    "ARP":     {"pacotes": 0, "bytes": 0},
    "ICMP":    {"pacotes": 0, "bytes": 0},
    "TCP":     {"pacotes": 0, "bytes": 0},
    "UDP":     {"pacotes": 0, "bytes": 0},
    "UNKNOWN": {"pacotes": 0, "bytes": 0},
}
start_time = None  #preenchido quando a captura arranca
#---------------------------------------------------------------

def print_stats():
    #calcula totais gerais
    total_pkts  = sum(v["pacotes"] for v in stats.values())
    total_bytes = sum(v["bytes"]   for v in stats.values())

    #duração total da sessão de captura
    duracao  = datetime.datetime.now() - start_time
    segundos = duracao.total_seconds()

    print("\n" + "═" * 60)
    print(" 【 ESTATÍSTICAS DA CAPTURA 】")
    print("═" * 60)
    print(f"  ⏱︎  Duração       : {str(duracao).split('.')[0]}")
    print(f" ")
    print(f"  ❱  Total pacotes : {total_pkts}")
    print(f"  ❱  Total bytes   : {total_bytes} B  ({total_bytes/1024:.2f} KB)")
    if segundos > 0:
        print(f"  ❱  Débito médio  : {total_bytes/segundos:.1f} B/s")
    print("─" * 60)
    print(f"  {'Protocolo':<10} {'Pacotes':>8} {'%Pkts':>7} {'Bytes':>10} {'%Bytes':>8}")
    print("─" * 60)

    #ordena por pacotes - protocolo mais visto aparece primeiro
    for proto, dados in sorted(stats.items(), key=lambda x: x[1]["pacotes"], reverse=True):
        if dados["pacotes"] == 0:
            continue
        pct_pkts  = (dados["pacotes"] / total_pkts  * 100) if total_pkts  > 0 else 0
        pct_bytes = (dados["bytes"]   / total_bytes * 100) if total_bytes > 0 else 0

        #barra visual proporcional ao tráfego (máx 20 chars)
        barra = "█" * int(pct_pkts / 5) + "░" * (20 - int(pct_pkts / 5))

        print(f"  {proto:<10} {dados['pacotes']:>8} {pct_pkts:>6.1f}% {dados['bytes']:>10} {pct_bytes:>7.1f}%")
        print(f"  {'':10} {barra}")

    print("═" * 60 + "\n")


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

    #----------------------------------------------------------------
    #OPC1: atualiza contadores após processar o pacote 
    if proto in stats:
        stats[proto]["pacotes"] += 1
        stats[proto]["bytes"]   += len(pkt)
    else:
        stats["UNKNOWN"]["pacotes"] += 1
        stats["UNKNOWN"]["bytes"]   += len(pkt)
    #---------------------------------------------------------------


def main():
    #OPC1: registar tempo de início
    global start_time
    start_time = datetime.datetime.now()

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

    #OPC1: o scapy por vezes intercepta o ctrl+c antes do python, por isso  vamos tentar usar stop_filter para parar a captura de forma limpa (a verificar!)
    import signal

    stop = {"flag": False}

    def handle_sigint(sig, frame):
        stop["flag"] = True

    signal.signal(signal.SIGINT, handle_sigint)

    sniff(iface=args.interface, prn=lambda p: process_packet(p, args),
          store=0, stop_filter=lambda p: stop["flag"])

    print("\n[!] Captura terminada.")
    print_stats()

if __name__ == "__main__":
    main()