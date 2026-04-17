import argparse
from scapy.all import *
import datetime
import os
import signal

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

#OPCIONAL 2: calculo de RTT via ICMP
#guarda o timestamp dos echo requests pendentes {ip_src: timestamp}
icmp_pending = {}
rtt_samples  = []  #lista de RTTs calculados em ms

def print_stats():
    #cores ANSI para dar vida ao terminal
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    DIM    = "\033[2m"
    WHITE  = "\033[97m"

    #cor associada a cada protocolo
    proto_cores = {
        "TCP":     BLUE,
        "UDP":     CYAN,
        "ICMP":    GREEN,
        "ARP":     YELLOW,
        "UNKNOWN": DIM,
    }

    #calcula totais gerais
    total_pkts  = sum(v["pacotes"] for v in stats.values())
    total_bytes = sum(v["bytes"]   for v in stats.values())
    duracao     = datetime.datetime.now() - start_time
    segundos    = duracao.total_seconds()

    #header
    print(f"\n{CYAN}{'═' * 62}{RESET}")
    print(f"{BOLD}{CYAN}  >>>  PACKET SNIFFER  ·  RELATORIO DE CAPTURA{RESET}")
    print(f"{CYAN}{'═' * 62}{RESET}")
    print(f"  {DIM}duração   {RESET}{WHITE}{str(duracao).split('.')[0]}{RESET}")
    print(f"  {DIM}pacotes   {RESET}{WHITE}{total_pkts}{RESET}")
    print(f"  {DIM}bytes     {RESET}{WHITE}{total_bytes} B  ({total_bytes/1024:.2f} KB){RESET}")
    if segundos > 0:
        print(f"  {DIM}débito    {RESET}{WHITE}{total_bytes/segundos:.1f} B/s{RESET}")
    print(f"{CYAN}{'─' * 62}{RESET}")

    #cabeçalho da tabela
    print(f"  {BOLD}{'PROTO':<10} {'PKTS':>6}  {'%':>5}   {'BYTES':>10}  {'%':>5}   DISTRIBUIÇÃO{RESET}")
    print(f"{DIM}{'─' * 62}{RESET}")

    #linha por protocolo
    for proto, dados in sorted(stats.items(), key=lambda x: x[1]["pacotes"], reverse=True):
        if dados["pacotes"] == 0:
            continue

        cor       = proto_cores.get(proto, WHITE)
        pct_pkts  = (dados["pacotes"] / total_pkts  * 100) if total_pkts  > 0 else 0
        pct_bytes = (dados["bytes"]   / total_bytes * 100) if total_bytes > 0 else 0

        #barra proporcional colorida (max 20 chars)
        filled = int(pct_pkts / 5)
        barra  = f"{cor}{'█' * filled}{DIM}{'░' * (20 - filled)}{RESET}"

        print(f"  {cor}{BOLD}{proto:<10}{RESET} {WHITE}{dados['pacotes']:>6}{RESET}  {cor}{pct_pkts:>4.1f}%{RESET}   {WHITE}{dados['bytes']:>10}{RESET}  {cor}{pct_bytes:>4.1f}%{RESET}   {barra}")

    #OPC2: bloco de RTT no final do relatório
    if rtt_samples:
        print(f"{CYAN}{'─' * 62}{RESET}")
        print(f"  {BOLD}RTT MÉDIO (ICMP){RESET}")
        print(f"  {DIM}amostras  {RESET}{WHITE}{len(rtt_samples)}{RESET}")
        print(f"  {DIM}mínimo    {RESET}{YELLOW}{min(rtt_samples):.2f} ms{RESET}")
        print(f"  {DIM}máximo    {RESET}{YELLOW}{max(rtt_samples):.2f} ms{RESET}")
        print(f"  {DIM}média     {RESET}{YELLOW}{sum(rtt_samples)/len(rtt_samples):.2f} ms{RESET}")

    print(f"{CYAN}{'═' * 62}{RESET}\n")


def plot_stats():
    #OPC3: gráfico opcional (só corre se matplotlib estiver instalado)
    #para instalar: pip install matplotlib --break-system-packages
    try:
        import matplotlib.pyplot as plt
        import matplotlib.patches as patches
    except ImportError:
        print("  [!] matplotlib nao instalado - grafico ignorado.")
        print("  [!] para ativar: pip install matplotlib --break-system-packages\n")
        return

    total_pkts  = sum(v["pacotes"] for v in stats.values())
    total_bytes = sum(v["bytes"]   for v in stats.values())
    if total_pkts == 0:
        return

    dados_filtrados = {k: v for k, v in stats.items() if v["pacotes"] > 0}
    protocolos = list(dados_filtrados.keys())
    pacotes    = [v["pacotes"] for v in dados_filtrados.values()]
    bytes_val  = [v["bytes"]   for v in dados_filtrados.values()]
    pct_pkts   = [p / total_pkts  * 100 for p in pacotes]
    pct_bytes  = [b / total_bytes * 100 for b in bytes_val]

    cores_map  = {"TCP": "#4C9BE8", "UDP": "#50E3C2", "ICMP": "#7ED321",
                  "ARP": "#F5A623", "UNKNOWN": "#9B9B9B"}
    bar_cores  = [cores_map.get(p, "#AAAAAA") for p in protocolos]

    duracao  = datetime.datetime.now() - start_time
    segundos = duracao.total_seconds()
    debito   = f"{total_bytes/segundos:.0f} B/s" if segundos > 0 else "N/A"

    plt.style.use("dark_background")
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    fig.patch.set_facecolor("#0D1117")
    fig.suptitle("Packet Sniffer  ·  Relatório de Captura",
                 color="white", fontsize=13, fontweight="bold")

    #barras verticais: pacotes por protocolo
    bars = ax1.bar(protocolos, pacotes, color=bar_cores, width=0.5, zorder=3)
    ax1.set_facecolor("#161B22")
    ax1.set_title("Pacotes por Protocolo", color="white", pad=10)
    ax1.set_ylabel("Nº de Pacotes", color="#8B949E")
    ax1.tick_params(colors="white")
    ax1.grid(axis="y", color="#30363D", zorder=0)
    for spine in ax1.spines.values():
        spine.set_edgecolor("#30363D")
    for bar, pct in zip(bars, pct_pkts):
        ax1.text(bar.get_x() + bar.get_width() / 2,
                 bar.get_height() + max(pacotes) * 0.02,
                 f"{pct:.1f}%", ha="center", va="bottom",
                 color="white", fontsize=9, fontweight="bold")

    #barras horizontais: bytes por protocolo
    y_pos = range(len(protocolos))
    hbars = ax2.barh(list(y_pos), pct_bytes, color=bar_cores, height=0.5, zorder=3)
    ax2.set_facecolor("#161B22")
    ax2.set_title("Distribuição de Bytes (%)", color="white", pad=10)
    ax2.set_yticks(list(y_pos))
    ax2.set_yticklabels(protocolos, color="white")
    ax2.tick_params(colors="white")
    ax2.grid(axis="x", color="#30363D", zorder=0)
    for spine in ax2.spines.values():
        spine.set_edgecolor("#30363D")
    for bar, bval in zip(hbars, bytes_val):
        ax2.text(bar.get_width() + 1,
                 bar.get_y() + bar.get_height() / 2,
                 f"{bval} B", va="center", color="white", fontsize=8)
    ax2.set_xlim(0, 115)

    fig.text(0.5, -0.02,
             f"Duração: {str(duracao).split('.')[0]}   |   "
             f"Total: {total_pkts} pkts  /  {total_bytes/1024:.1f} KB   |   "
             f"Débito: {debito}",
             ha="center", color="#8B949E", fontsize=8)

    plt.tight_layout()
    plt.savefig("captura_stats.png", dpi=150, bbox_inches="tight",
                facecolor="#0D1117")
    print(f"  [->] grafico guardado em captura_stats.png")

    #tenta abrir o ficheiro automaticamente
    import subprocess
    try:
        subprocess.Popen(["xdg-open", "captura_stats.png"])
    except Exception:
        pass


def process_packet(pkt, args):
    # 1. FILTROS DE EXECUÇÃO
    # Filtro de Protocolo
    if args.protocol:
        p_lower = args.protocol.lower()
        if p_lower == "icmp" and ICMP not in pkt: return
        if p_lower == "tcp"  and TCP  not in pkt: return
        if p_lower == "udp"  and UDP  not in pkt: return
        if p_lower == "arp"  and ARP  not in pkt: return

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
    info  = ""

    # 2. PARSING
    if ARP in pkt:
        proto = "ARP"
        op    = "Request" if pkt[ARP].op == 1 else "Reply"
        info  = f"{op}: {pkt[ARP].psrc} -> {pkt[ARP].pdst}"
    elif IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        ttl    = pkt[IP].ttl
        if ICMP in pkt:
            proto = "ICMP"
            info  = f"Type {pkt[ICMP].type} (TTL:{ttl})"

            #OPC2: calculo de RTT
            #echo request: guarda o timestamp indexado pelo ip de origem
            if pkt[ICMP].type == 8:
                icmp_pending[src_ip] = pkt.time
            #echo reply: emparelha com o request e calcula o RTT
            elif pkt[ICMP].type == 0:
                if dst_ip in icmp_pending:
                    rtt_ms = (pkt.time - icmp_pending.pop(dst_ip)) * 1000
                    rtt_samples.append(rtt_ms)
                    info = f"Type 0 | RTT: {rtt_ms:.2f} ms (TTL:{ttl})"

        elif TCP in pkt:
            proto = "TCP"
            info  = f"{src_ip}:{pkt[TCP].sport} -> {dst_ip}:{pkt[TCP].dport} [Flags: {pkt[TCP].flags}, TTL:{ttl}]"
        elif UDP in pkt:
            proto = "UDP"
            info  = f"{src_ip}:{pkt[UDP].sport} -> {dst_ip}:{pkt[UDP].dport} [TTL:{ttl}]"

    summary_line = f"[{time_now}] {proto} | {len(pkt)} bytes | {info if info else pkt.summary()}"

    if args.live: print(summary_line)
    if args.log:
        with open(args.log, "a") as f:
            f.write(summary_line + "\n")

    #OPC1: atualiza contadores após processar o pacote
    if proto in stats:
        stats[proto]["pacotes"] += 1
        stats[proto]["bytes"]   += len(pkt)
    else:
        stats["UNKNOWN"]["pacotes"] += 1
        stats["UNKNOWN"]["bytes"]   += len(pkt)


def main():
    #OPC1: registar tempo de início
    global start_time
    start_time = datetime.datetime.now()

    parser = argparse.ArgumentParser(description="O meu Packet Sniffer RC")
    parser.add_argument("-i", "--interface", help="Seleciona a interface de rede a capturar")
    parser.add_argument("-p", "--protocol",  help="Filtra por protocolo (arp, icmp, tcp, udp)")
    parser.add_argument("--ip",              help="Filtra por endereço IP de origem ou destino")
    parser.add_argument("--mac",             help="Filtra por endereço MAC")
    parser.add_argument("-l", "--log",       help="Ativa modo log e define ficheiro de saída")
    parser.add_argument("--live",            action="store_true", help="Ativa impressão em tempo real na consola")
    parser.add_argument("--graph",           action="store_true", help="Gera grafico no final (requer matplotlib)")

    args = parser.parse_args()

    if not args.live and not args.log:
        print("\n[!] AVISO: Define --live ou --log para ver resultados.\n")

    print("A iniciar captura...")

    stop = {"flag": False}

    def handle_sigint(sig, frame):
        stop["flag"] = True

    signal.signal(signal.SIGINT, handle_sigint)

    sniff(iface=args.interface, prn=lambda p: process_packet(p, args),
          store=0, stop_filter=lambda p: stop["flag"])

    print("\n[!] Captura terminada.")
    print_stats()

    #OPC3: grafico só se o utilizador pedir explicitamente com --graph
    if args.graph:
        plot_stats()

if __name__ == "__main__":
    main()