import argparse
from scapy.all import *
import datetime
import os
import signal
import socket

#OPCIONAL 1: estatísticas finais
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
icmp_pending = {}
rtt_samples  = []

#OPCIONAL 4: DNS resolver com cache para nao repetir queries
dns_cache = {}

#OPCIONAL 5: deteção de anomalias
scan_tracker  = {}  #{ip: {portas tentadas}}
icmp_tracker  = {}  #{ip: [timestamps]}
alertas       = []  #lista de alertas gerados durante a sessão

def resolver_hostname(ip):
    #devolve da cache se já foi resolvido antes
    if ip in dns_cache:
        return dns_cache[ip]
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        #encurta hostnames muito longos para nao poluir o output
        if len(hostname) > 35:
            hostname = hostname[:32] + "..."
        dns_cache[ip] = hostname
    except Exception:
        dns_cache[ip] = ip
    return dns_cache[ip]

def verificar_anomalias(pkt, src_ip, proto, args):
    #OPC5: deteta port scan; um IP a tentar muitas portas diferentes em pouco tempo
    if proto == "TCP" and TCP in pkt:
        porta_dst = pkt[TCP].dport
        if src_ip not in scan_tracker:
            scan_tracker[src_ip] = set()
        scan_tracker[src_ip].add(porta_dst)
        #alerta se um IP tentou mais de 15 portas distintas
        if len(scan_tracker[src_ip]) == 15:
            alerta = f"[ALERTA] possivel port scan - {src_ip} tentou {len(scan_tracker[src_ip])} portas distintas"
            if alerta not in alertas:
                alertas.append(alerta)
                if args.live:
                    print(f"\033[91m{alerta}\033[0m")

    #OPC5: deteta ICMP flood; mais de 20 pings por segundo do mesmo IP
    if proto == "ICMP" and ICMP in pkt and pkt[ICMP].type == 8:
        agora = pkt.time
        if src_ip not in icmp_tracker:
            icmp_tracker[src_ip] = []
        icmp_tracker[src_ip].append(agora)
        #remove timestamps com mais de 1 segundo
        icmp_tracker[src_ip] = [t for t in icmp_tracker[src_ip] if agora - t <= 1.0]
        if len(icmp_tracker[src_ip]) > 20:
            alerta = f"[ALERTA] flood ICMP detetado - {src_ip} enviou {len(icmp_tracker[src_ip])} pings em 1s"
            if alerta not in alertas:
                alertas.append(alerta)
                if args.live:
                    print(f"\033[91m{alerta}\033[0m")

def print_stats():
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    BLUE   = "\033[94m"
    DIM    = "\033[2m"
    WHITE  = "\033[97m"

    proto_cores = {
        "TCP":     BLUE,
        "UDP":     CYAN,
        "ICMP":    GREEN,
        "ARP":     YELLOW,
        "UNKNOWN": DIM,
    }

    total_pkts  = sum(v["pacotes"] for v in stats.values())
    total_bytes = sum(v["bytes"]   for v in stats.values())
    duracao     = datetime.datetime.now() - start_time
    segundos    = duracao.total_seconds()

    print(f"\n{CYAN}{'═' * 62}{RESET}")
    print(f"{BOLD}{CYAN}  >>>  PACKET SNIFFER  ·  RELATÓRIO DE CAPTURA  <<<{RESET}")
    print(f"{CYAN}{'═' * 62}{RESET}")
    print(f"  {DIM}【 duração   {RESET}{WHITE}{str(duracao).split('.')[0]}{RESET}")
    print(f"  {DIM}【 pacotes   {RESET}{WHITE}{total_pkts}{RESET}")
    print(f"  {DIM}【 bytes     {RESET}{WHITE}{total_bytes} B  ({total_bytes/1024:.2f} KB){RESET}")
    if segundos > 0:
        print(f"  {DIM}【 débito    {RESET}{WHITE}{total_bytes/segundos:.1f} B/s{RESET}")
    print(f"{CYAN}{'─' * 62}{RESET}")

    print(f"  {BOLD}{'PROTO':<10} {'PKTS':>6}  {'%':>5}   {'BYTES':>10}  {'%':>5}   DISTRIBUIÇÃO{RESET}")
    print(f"{DIM}{'─' * 62}{RESET}")

    for proto, dados in sorted(stats.items(), key=lambda x: x[1]["pacotes"], reverse=True):
        if dados["pacotes"] == 0:
            continue
        cor       = proto_cores.get(proto, WHITE)
        pct_pkts  = (dados["pacotes"] / total_pkts  * 100) if total_pkts  > 0 else 0
        pct_bytes = (dados["bytes"]   / total_bytes * 100) if total_bytes > 0 else 0
        filled    = int(pct_pkts / 5)
        barra     = f"{cor}{'█' * filled}{DIM}{'░' * (20 - filled)}{RESET}"
        print(f"  {cor}{BOLD}{proto:<10}{RESET} {WHITE}{dados['pacotes']:>6}{RESET}  {cor}{pct_pkts:>4.1f}%{RESET}   {WHITE}{dados['bytes']:>10}{RESET}  {cor}{pct_bytes:>4.1f}%{RESET}   {barra}")

    #OPC2: bloco de RTT
    if rtt_samples:
        print(f"{CYAN}{'─' * 62}{RESET}")
        print(f"  {BOLD}RTT MÉDIO (ICMP){RESET}")
        print(f"  {DIM}amostras  {RESET}{WHITE}{len(rtt_samples)}{RESET}")
        print(f"  {DIM}mínimo    {RESET}{YELLOW}{min(rtt_samples):.2f} ms{RESET}")
        print(f"  {DIM}máximo    {RESET}{YELLOW}{max(rtt_samples):.2f} ms{RESET}")
        print(f"  {DIM}média     {RESET}{YELLOW}{sum(rtt_samples)/len(rtt_samples):.2f} ms{RESET}")

    #OPC5: bloco de alertas de segurança
    if alertas:
        print(f"{RED}{'─' * 62}{RESET}")
        print(f"  {BOLD}{RED}ALERTAS DE SEGURANÇA DETETADOS{RESET}")
        for a in alertas:
            print(f"  {RED}{a}{RESET}")

    #OPC4: top 5 hostnames resolvidos mais vistos
    if dns_cache:
        hostname_counts = {}
        for ip, hostname in dns_cache.items():
            if hostname != ip:
                hostname_counts[hostname] = hostname_counts.get(hostname, 0) + 1
        if hostname_counts:
            top = sorted(hostname_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            print(f"{CYAN}{'─' * 62}{RESET}")
            print(f"  {BOLD}TOP HOSTNAMES RESOLVIDOS{RESET}")
            for hostname, _ in top:
                print(f"  {GREEN}→ {hostname}{RESET}")

    print(f"{CYAN}{'═' * 62}{RESET}\n")


def plot_stats():
    #OPC3: gráfico opcional (só corre se matplotlib estiver instalado)
    try:
        import matplotlib.pyplot as plt
        import matplotlib.patches as patches
    except ImportError:
        print("  [!] matplotlib não instalado - gráfico ignorado.")
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
    print(f"  [->] gráfico guardado em captura_stats.png")

    import subprocess
    try:
        subprocess.Popen(["xdg-open", "captura_stats.png"])
    except Exception:
        pass


def process_packet(pkt, args):
    # 1. FILTROS DE EXECUÇÃO
    if args.protocol:
        p_lower = args.protocol.lower()
        if p_lower == "icmp" and ICMP not in pkt: return
        if p_lower == "tcp"  and TCP  not in pkt: return
        if p_lower == "udp"  and UDP  not in pkt: return
        if p_lower == "arp"  and ARP  not in pkt: return

    if args.ip:
        if IP not in pkt or (pkt[IP].src != args.ip and pkt[IP].dst != args.ip):
            return

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
            #OPC2: cálculo de RTT
            if pkt[ICMP].type == 8:
                icmp_pending[src_ip] = pkt.time
            elif pkt[ICMP].type == 0:
                if dst_ip in icmp_pending:
                    rtt_ms = (pkt.time - icmp_pending.pop(dst_ip)) * 1000
                    rtt_samples.append(rtt_ms)
                    info = f"Type 0 | RTT: {rtt_ms:.2f} ms (TTL:{ttl})"

        elif TCP in pkt:
            proto = "TCP"
            #OPC4: resolve o hostname de destino
            host  = resolver_hostname(dst_ip)
            info  = f"{src_ip}:{pkt[TCP].sport} -> {host}:{pkt[TCP].dport} [Flags: {pkt[TCP].flags}, TTL:{ttl}]"

        elif UDP in pkt:
            proto = "UDP"
            #OPC4: resolve o hostname de destino
            host  = resolver_hostname(dst_ip)
            info  = f"{src_ip}:{pkt[UDP].sport} -> {host}:{pkt[UDP].dport} [TTL:{ttl}]"

        #OPC5: verifica anomalias em tempo real
        verificar_anomalias(pkt, src_ip, proto, args)

    mac_info     = f"{pkt.src} -> {pkt.dst}"
    summary_line = f"[{time_now}] [{args.interface or 'any'}] {proto} | {len(pkt)} bytes | {mac_info} | {info if info else pkt.summary()}"

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
    parser.add_argument("--duration",        type=int, default=0,
                        help="Para a captura automaticamente após N segundos (ex: --duration 30)")

    args = parser.parse_args()

    if not args.live and not args.log:
        print("\n[!] AVISO: Define --live ou --log para ver resultados.\n")

    print(f"A capturar em {args.interface or 'todas as interfaces'}... (Ctrl+C para parar)")

    #OPC6: informa o utilizador se a captura tem duração limitada
    if args.duration > 0:
        print(f"  [→] captura limitada a {args.duration} segundos")

    stop = {"flag": False}

    def handle_sigint(sig, frame):
        stop["flag"] = True

    signal.signal(signal.SIGINT, handle_sigint)

    #OPC6: stop_filter verifica tanto o Ctrl+C como o tempo limite
    def deve_parar(pkt):
        if stop["flag"]:
            return True
        if args.duration > 0:
            elapsed = (datetime.datetime.now() - start_time).total_seconds()
            if elapsed >= args.duration:
                return True
        return False

    try:
        sniff(iface=args.interface, prn=lambda p: process_packet(p, args),
              store=0, stop_filter=deve_parar)
    except Exception as e:
        print(f"[!] Erro na captura: {e}")

    print("\n[!] Captura terminada.")
    print_stats()

    #OPC3: gráfico só se o utilizador pedir explicitamente com --graph
    if args.graph:
        plot_stats()

if __name__ == "__main__":
    main()