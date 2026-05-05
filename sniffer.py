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

#lista global onde todos os pacotes ficam guardados em memoria
trafico_capturado = []

#hashtable para pesquisa rapida pos-captura
#indexa pacotes por proto, src_ip, dst_ip, src_port, dst_port
hashtable = {
    "proto":    {},
    "src_ip":   {},
    "dst_ip":   {},
    "src_port": {},
    "dst_port": {},
}

#OPCIONAL 7: mapping de portas conhecidas para servicos
#mostra :443 (HTTPS) em vez de so :443 no output
PORT_SERVICES = {
    20: "FTP-data",   21: "FTP",       22: "SSH",       23: "Telnet",
    25: "SMTP",       53: "DNS",       67: "DHCP-srv",  68: "DHCP-cli",
    80: "HTTP",       110: "POP3",     123: "NTP",      143: "IMAP",
    443: "HTTPS",     465: "SMTPS",    587: "SMTP-sub",
    993: "IMAPS",     995: "POP3S",    3306: "MySQL",   5432: "PostgreSQL",
    5353: "mDNS",     8080: "HTTP-alt", 8443: "HTTPS-alt"
}


def porta_servico(porta):
    #devolve o nome do servico se a porta for conhecida
    servico = PORT_SERVICES.get(porta)
    return f" ({servico})" if servico else ""


def resolver_hostname(ip):
    #devolve da cache se ja foi resolvido antes
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
    #OPC5: deteta port scan - um IP a tentar muitas portas diferentes
    if proto == "TCP" and TCP in pkt:
        porta_dst = pkt[TCP].dport
        if src_ip not in scan_tracker:
            scan_tracker[src_ip] = set()
        scan_tracker[src_ip].add(porta_dst)
        #alerta se um IP tentou mais de 15 portas distintas
        if len(scan_tracker[src_ip]) == 15:
            alerta = f"[ALERTA] possível port scan - {src_ip} tentou {len(scan_tracker[src_ip])} portas distintas"
            if alerta not in alertas:
                alertas.append(alerta)
                if args.live:
                    print(f"\033[91m{alerta}\033[0m")

    #OPC5: deteta ICMP flood - mais de 20 pings por segundo do mesmo IP
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


def guardar_trafico(dados_pkt):
    #guarda o pacote na lista global e indexa-o na hashtable
    trafico_capturado.append(dados_pkt)
    indexar_na_hashtable(dados_pkt)


def indexar_na_hashtable(dados_pkt):
    #insere o pacote em todas as categorias relevantes da hashtable
    def _inserir(categoria, chave):
        if chave is None:
            return
        chave = str(chave)
        if chave not in hashtable[categoria]:
            hashtable[categoria][chave] = []
        hashtable[categoria][chave].append(dados_pkt)

    _inserir("proto",    dados_pkt.get("proto"))
    _inserir("src_ip",   dados_pkt.get("src_ip"))
    _inserir("dst_ip",   dados_pkt.get("dst_ip"))
    _inserir("src_port", dados_pkt.get("src_port"))
    _inserir("dst_port", dados_pkt.get("dst_port"))


def filtrar_hashtable(proto=None, src_ip=None, dst_ip=None,
                      src_port=None, dst_port=None,
                      tamanho_min=None, tamanho_max=None,
                      hora_inicio=None, hora_fim=None):
    #pesquisa pacotes na hashtable combinando varios filtros
    #devolve lista de pacotes que passam em todos os filtros

    candidatos = None  #None = ainda nao filtramos nada

    def intersectar(categoria, chave):
        #vai cortando a lista de candidatos a cada filtro novo
        nonlocal candidatos
        if chave is None:
            return
        chave = str(chave)
        bucket = hashtable[categoria].get(chave, [])
        ids_bucket = {id(p) for p in bucket}
        if candidatos is None:
            candidatos = [p for p in bucket]
        else:
            candidatos = [p for p in candidatos if id(p) in ids_bucket]

    intersectar("proto",    proto)
    intersectar("src_ip",   src_ip)
    intersectar("dst_ip",   dst_ip)
    intersectar("src_port", src_port)
    intersectar("dst_port", dst_port)

    #se nenhum filtro indexado foi dado, parte de tudo
    if candidatos is None:
        candidatos = list(trafico_capturado)

    #filtros nao indexados (tamanho e hora) aplicados no fim
    resultado = []
    for pkt in candidatos:
        if tamanho_min is not None and pkt.get("tamanho", 0) < tamanho_min:
            continue
        if tamanho_max is not None and pkt.get("tamanho", 0) > tamanho_max:
            continue
        if hora_inicio is not None and pkt.get("timestamp", "") < hora_inicio:
            continue
        if hora_fim is not None and pkt.get("timestamp", "") > hora_fim:
            continue
        resultado.append(pkt)

    return resultado


def guardar_trafico_ficheiro(caminho="trafico.txt"):
    #escreve todos os pacotes capturados num .txt com cabeçalho e resumo
    if not trafico_capturado:
        print("  [!] Nenhum pacote para guardar.")
        return

    try:
        with open(caminho, "w", encoding="utf-8") as f:

            #cabeçalho do ficheiro
            agora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write("=" * 70 + "\n")
            f.write("  PACKET SNIFFER — REGISTO DE TRÁFEGO\n")
            f.write(f"  Gerado em: {agora}\n")
            f.write(f"  Total de pacotes: {len(trafico_capturado)}\n")
            f.write("=" * 70 + "\n\n")

            #uma linha por pacote
            for pkt in trafico_capturado:
                src = pkt.get("src_ip") or pkt.get("src_mac", "?")
                dst = pkt.get("dst_ip") or pkt.get("dst_mac", "?")

                #acrescenta porta se existir
                if pkt.get("src_port"):
                    src = f"{src}:{pkt['src_port']}"
                if pkt.get("dst_port"):
                    dst = f"{dst}:{pkt['dst_port']}"

                linha = (
                    f"[{pkt.get('timestamp', '?')}] "
                    f"{pkt.get('proto', 'UNKNOWN'):<7} | "
                    f"{pkt.get('tamanho', 0):>5} bytes | "
                    f"{src} -> {dst} | "
                    f"{pkt.get('info', '')}\n"
                )
                f.write(linha)

            #resumo por protocolo no fim
            f.write("\n" + "=" * 70 + "\n")
            f.write("  RESUMO POR PROTOCOLO\n")
            f.write("-" * 70 + "\n")

            contagem = {}
            total_bytes = 0
            for pkt in trafico_capturado:
                p = pkt.get("proto", "UNKNOWN")
                contagem[p] = contagem.get(p, {"pacotes": 0, "bytes": 0})
                contagem[p]["pacotes"] += 1
                contagem[p]["bytes"]   += pkt.get("tamanho", 0)
                total_bytes            += pkt.get("tamanho", 0)

            for proto, dados in sorted(contagem.items(), key=lambda x: x[1]["pacotes"], reverse=True):
                pct = dados["pacotes"] / len(trafico_capturado) * 100
                f.write(
                    f"  {proto:<8} {dados['pacotes']:>6} pacotes "
                    f"({pct:>5.1f}%)   {dados['bytes']:>8} bytes\n"
                )

            f.write("-" * 70 + "\n")
            f.write(f"  TOTAL    {len(trafico_capturado):>6} pacotes            {total_bytes:>8} bytes\n")
            f.write("=" * 70 + "\n")

        print(f"  [->] tráfego guardado em '{caminho}'")

    except OSError as e:
        print(f"  [!] Erro ao guardar ficheiro: {e}")


def print_stats():
    #cores ANSI para dar um ar mais vivo ao terminal
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

    #cabeçalho do relatório
    print(f"\n{CYAN}{'═' * 62}{RESET}")
    print(f"{BOLD}{CYAN}  >>>  PACKET SNIFFER  ·  RELATÓRIO DE CAPTURA  <<<{RESET}")
    print(f"{CYAN}{'═' * 62}{RESET}")
    print(f"  {DIM}【 duração   {RESET}{WHITE}{str(duracao).split('.')[0]}{RESET}")
    print(f"  {DIM}【 pacotes   {RESET}{WHITE}{total_pkts}{RESET}")
    print(f"  {DIM}【 bytes     {RESET}{WHITE}{total_bytes} B  ({total_bytes/1024:.2f} KB){RESET}")
    if segundos > 0:
        print(f"  {DIM}【 débito    {RESET}{WHITE}{total_bytes/segundos:.1f} B/s{RESET}")
    print(f"{CYAN}{'─' * 62}{RESET}")

    #cabeçalho da tabela
    print(f"  {BOLD}{'PROTO':<10} {'PKTS':>6}  {'%':>5}   {'BYTES':>10}  {'%':>5}   DISTRIBUIÇÃO{RESET}")
    print(f"{DIM}{'─' * 62}{RESET}")

    #linha por protocolo com barra proporcional
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

    #OPC4: top 5 hostnames mais vistos
    if dns_cache:
        hostname_counts = {}
        for ip, hostname in dns_cache.items():
            if hostname != ip:  #so conta IPs que foram resolvidos para nome
                hostname_counts[hostname] = hostname_counts.get(hostname, 0) + 1
        if hostname_counts:
            top = sorted(hostname_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            print(f"{CYAN}{'─' * 62}{RESET}")
            print(f"  {BOLD}TOP HOSTNAMES RESOLVIDOS{RESET}")
            for hostname, _ in top:
                print(f"  {GREEN}→ {hostname}{RESET}")

    print(f"{CYAN}{'═' * 62}{RESET}\n")


def plot_stats():
    #OPC3: grafico opcional, so corre se matplotlib estiver instalado
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

    #barras verticais com pacotes por protocolo
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

    #barras horizontais com bytes por protocolo
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

    #tenta abrir o ficheiro automaticamente
    import subprocess
    try:
        subprocess.Popen(["xdg-open", "captura_stats.png"])
    except Exception:
        pass


def process_packet(pkt, args):
    #1. filtros de execução - rejeita pacotes que nao interessam
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

    #campos que vao para a hashtable
    src_ip   = None
    dst_ip   = None
    src_port = None
    dst_port = None

    #2. parsing por protocolo
    if ARP in pkt:
        proto  = "ARP"
        op     = "Request" if pkt[ARP].op == 1 else "Reply"
        src_ip = pkt[ARP].psrc
        dst_ip = pkt[ARP].pdst
        info   = f"{op}: {src_ip} -> {dst_ip}"
    elif IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        ttl    = pkt[IP].ttl
        if ICMP in pkt:
            proto = "ICMP"
            info  = f"Type {pkt[ICMP].type} (TTL:{ttl})"
            #OPC2: calculo de RTT
            if pkt[ICMP].type == 8:
                #echo request: guarda o timestamp pelo IP de origem
                icmp_pending[src_ip] = pkt.time
            elif pkt[ICMP].type == 0:
                #echo reply: emparelha com o request e calcula o RTT
                if dst_ip in icmp_pending:
                    rtt_ms = (pkt.time - icmp_pending.pop(dst_ip)) * 1000
                    rtt_samples.append(rtt_ms)
                    info = f"Type 0 | RTT: {rtt_ms:.2f} ms (TTL:{ttl})"

        elif TCP in pkt:
            proto    = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            #OPC4: resolve hostname / OPC7: identifica servico
            host = resolver_hostname(dst_ip)
            info = f"{src_ip}:{src_port} -> {host}:{dst_port}{porta_servico(dst_port)} [Flags: {pkt[TCP].flags}, TTL:{ttl}]"

        elif UDP in pkt:
            proto    = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            #OPC4: resolve hostname / OPC7: identifica servico
            host = resolver_hostname(dst_ip)
            info = f"{src_ip}:{src_port} -> {host}:{dst_port}{porta_servico(dst_port)} [TTL:{ttl}]"

        #OPC5: verifica anomalias em tempo real
        verificar_anomalias(pkt, src_ip, proto, args)

    mac_info     = f"{pkt.src} -> {pkt.dst}"
    summary_line = f"[{time_now}] [{args.interface or 'any'}] {proto} | {len(pkt)} bytes | {mac_info} | {info if info else pkt.summary()}"

    if args.live: print(summary_line)
    if args.log:
        with open(args.log, "a") as f:
            f.write(summary_line + "\n")

    #OPC1: atualiza contadores apos processar o pacote
    if proto in stats:
        stats[proto]["pacotes"] += 1
        stats[proto]["bytes"]   += len(pkt)
    else:
        stats["UNKNOWN"]["pacotes"] += 1
        stats["UNKNOWN"]["bytes"]   += len(pkt)

    #guarda o pacote na lista global e indexa na hashtable
    dados_pkt = {
        "timestamp": time_now,
        "proto":     proto,
        "tamanho":   len(pkt),
        "src_mac":   pkt.src,
        "dst_mac":   pkt.dst,
        "src_ip":    src_ip,
        "dst_ip":    dst_ip,
        "src_port":  src_port,
        "dst_port":  dst_port,
        "info":      info if info else pkt.summary(),
    }
    guardar_trafico(dados_pkt)


def mostrar_filtrado(proto=None, src_ip=None, dst_ip=None,
                     src_port=None, dst_port=None,
                     tamanho_min=None, tamanho_max=None,
                     hora_inicio=None, hora_fim=None):
    #usa filtrar_hashtable() e imprime os resultados com cores
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
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

    resultados = filtrar_hashtable(
        proto=proto, src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        tamanho_min=tamanho_min, tamanho_max=tamanho_max,
        hora_inicio=hora_inicio, hora_fim=hora_fim,
    )

    #cabeçalho com os filtros ativos
    filtros_ativos = {
        "proto": proto, "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": src_port, "dst_port": dst_port,
        "tamanho_min": tamanho_min, "tamanho_max": tamanho_max,
        "hora_inicio": hora_inicio, "hora_fim": hora_fim,
    }
    descricao = "  ".join(
        f"{k}={v}" for k, v in filtros_ativos.items() if v is not None
    ) or "nenhum (todos os pacotes)"

    print(f"\n{CYAN}{'═' * 70}{RESET}")
    print(f"{BOLD}{CYAN}  FILTRO DE TRÁFEGO{RESET}")
    print(f"{CYAN}{'─' * 70}{RESET}")
    print(f"  {DIM}filtros   {RESET}{WHITE}{descricao}{RESET}")
    print(f"  {DIM}resultado {RESET}{WHITE}{len(resultados)} pacote(s) encontrado(s){RESET}")
    print(f"{CYAN}{'─' * 70}{RESET}")

    if not resultados:
        print(f"  {YELLOW}Nenhum pacote corresponde aos filtros indicados.{RESET}")
        print(f"{CYAN}{'═' * 70}{RESET}\n")
        return

    #cabeçalho da tabela
    print(
        f"  {BOLD}"
        f"{'HORA':<10} {'PROTO':<7} {'BYTES':>6}  "
        f"{'ORIGEM':<26} {'DESTINO':<26} INFO{RESET}"
    )
    print(f"{DIM}{'─' * 70}{RESET}")

    #uma linha por pacote
    for pkt in resultados:
        p   = pkt.get("proto", "UNKNOWN")
        cor = proto_cores.get(p, WHITE)

        src = pkt.get("src_ip") or pkt.get("src_mac", "?")
        dst = pkt.get("dst_ip") or pkt.get("dst_mac", "?")
        if pkt.get("src_port"):
            src = f"{src}:{pkt['src_port']}"
        if pkt.get("dst_port"):
            dst = f"{dst}:{pkt['dst_port']}"

        #trunca strings longas para caber na tabela
        src  = src[:25]  if len(src)  > 25 else src
        dst  = dst[:25]  if len(dst)  > 25 else dst
        info = pkt.get("info", "")
        info = info[:35] if len(info) > 35 else info

        print(
            f"  {WHITE}{pkt.get('timestamp','?'):<10}{RESET}"
            f" {cor}{BOLD}{p:<7}{RESET}"
            f" {WHITE}{pkt.get('tamanho',0):>6}{RESET}"
            f"  {src:<26} {dst:<26}"
            f" {DIM}{info}{RESET}"
        )

    #rodapé com totais
    total_bytes = sum(p.get("tamanho", 0) for p in resultados)
    print(f"{CYAN}{'─' * 70}{RESET}")
    print(f"  {DIM}total  {RESET}{WHITE}{len(resultados)} pacotes  /  {total_bytes} bytes  ({total_bytes/1024:.2f} KB){RESET}")
    print(f"{CYAN}{'═' * 70}{RESET}\n")


def main():
    #OPC1: registar tempo de inicio
    global start_time
    start_time = datetime.datetime.now()

    parser = argparse.ArgumentParser(description="O meu Packet Sniffer RC")
    parser.add_argument("-i", "--interface", help="Seleciona a interface de rede a capturar")
    parser.add_argument("-p", "--protocol",  help="Filtra por protocolo (arp, icmp, tcp, udp)")
    parser.add_argument("--ip",              help="Filtra por endereço IP de origem ou destino")
    parser.add_argument("--mac",             help="Filtra por endereço MAC")
    parser.add_argument("-l", "--log",       help="Ativa modo log e define ficheiro de saída")
    parser.add_argument("--live",            action="store_true", help="Ativa impressão em tempo real na consola")
    parser.add_argument("--graph",           action="store_true", help="Gera gráfico no final (requer matplotlib)")
    parser.add_argument("--duration",        type=int, default=0,
                        help="Para a captura automaticamente após N segundos (ex: --duration 30)")
    parser.add_argument("--save",            nargs="?", const="trafico.txt", metavar="FICHEIRO",
                        help="Guarda o tráfego capturado num ficheiro .txt (default: trafico.txt)")
    #OPC8: filtro BPF nativo do Scapy estilo tcpdump/Wireshark
    parser.add_argument("--bpf",             metavar="EXPRESSAO",
                        help="Filtro BPF estilo tcpdump (ex: 'tcp port 443', 'icmp', 'host 8.8.8.8')")

    #filtros pos-captura aplicados sobre a hashtable
    fg = parser.add_argument_group("filtros pós-captura (aplicados no fim sobre a hashtable)")
    fg.add_argument("--fproto",  metavar="PROTO",    help="Filtra resultado por protocolo  ex: TCP")
    fg.add_argument("--fsrc",    metavar="IP",       help="Filtra por IP de origem         ex: 192.168.1.1")
    fg.add_argument("--fdst",    metavar="IP",       help="Filtra por IP de destino        ex: 8.8.8.8")
    fg.add_argument("--fsport",  metavar="PORTA",    type=int, help="Filtra por porta de origem  ex: 443")
    fg.add_argument("--fdport",  metavar="PORTA",    type=int, help="Filtra por porta de destino ex: 80")
    fg.add_argument("--fmin",    metavar="BYTES",    type=int, help="Tamanho mínimo em bytes     ex: 100")
    fg.add_argument("--fmax",    metavar="BYTES",    type=int, help="Tamanho máximo em bytes     ex: 1500")
    fg.add_argument("--fhi",     metavar="HH:MM:SS", help="Hora de início do intervalo    ex: 10:00:00")
    fg.add_argument("--fhf",     metavar="HH:MM:SS", help="Hora de fim do intervalo       ex: 10:05:00")

    args = parser.parse_args()

    if not args.live and not args.log:
        print("\n[!] AVISO: Define --live ou --log para ver resultados.\n")

    print(f"A capturar em {args.interface or 'todas as interfaces'}... (Ctrl+C para parar)")

    #OPC6: avisa se a captura tem duração limitada
    if args.duration > 0:
        print(f"  [→] captura limitada a {args.duration} segundos")

    #OPC8: avisa se um filtro BPF foi aplicado
    if args.bpf:
        print(f"  [→] filtro BPF ativo: {args.bpf}")

    stop = {"flag": False}

    def handle_sigint(sig, frame):
        stop["flag"] = True

    signal.signal(signal.SIGINT, handle_sigint)

    #OPC6: stop_filter para o Ctrl+C ou o tempo limite
    def deve_parar(pkt):
        if stop["flag"]:
            return True
        if args.duration > 0:
            elapsed = (datetime.datetime.now() - start_time).total_seconds()
            if elapsed >= args.duration:
                return True
        return False

    try:
        #OPC8: passa o filtro BPF ao scapy via argumento filter
        sniff(iface=args.interface, prn=lambda p: process_packet(p, args),
              store=0, stop_filter=deve_parar, filter=args.bpf)
    except Exception as e:
        print(f"[!] Erro na captura: {e}")

    print("\n[!] Captura terminada.")
    print_stats()

    #OPC3: grafico so se o utilizador pedir explicitamente
    if args.graph:
        plot_stats()

    #guarda trafego em ficheiro se --save foi pedido
    if args.save:
        guardar_trafico_ficheiro(args.save)

    #mostra filtro pos-captura se pelo menos um filtro foi dado
    filtros_dados = any([
        args.fproto, args.fsrc, args.fdst, args.fsport, args.fdport,
        args.fmin, args.fmax, args.fhi, args.fhf
    ])
    if filtros_dados:
        mostrar_filtrado(
            proto       = args.fproto,
            src_ip      = args.fsrc,
            dst_ip      = args.fdst,
            src_port    = args.fsport,
            dst_port    = args.fdport,
            tamanho_min = args.fmin,
            tamanho_max = args.fmax,
            hora_inicio = args.fhi,
            hora_fim    = args.fhf,
        )


#menu interativo em linha de comandos

#cores reutilizadas no menu
_R  = "\033[0m"
_B  = "\033[1m"
_C  = "\033[96m"
_G  = "\033[92m"
_Y  = "\033[93m"
_RE = "\033[91m"
_D  = "\033[2m"
_W  = "\033[97m"

#estado partilhado da captura em curso (usado pela thread de sniff)
_captura_a_correr = {"flag": False}


def _cabecalho_menu():
    print(f"\n{_C}{'═' * 52}{_R}")
    print(f"{_B}{_C}   PACKET SNIFFER  ·  MENU PRINCIPAL{_R}")
    total = len(trafico_capturado)
    estado = f"{_G}EM CURSO{_R}" if _captura_a_correr["flag"] else f"{_D}parada{_R}"
    print(f"{_C}{'─' * 52}{_R}")
    print(f"  estado   : {estado}")
    print(f"  pacotes  : {_W}{total}{_R}")
    print(f"{_C}{'═' * 52}{_R}")


def _menu_iniciar_captura():
    #pede os parametros e arranca a captura numa thread separada
    import threading

    if _captura_a_correr["flag"]:
        print(f"  {_Y}[!] Já existe uma captura em curso. Para primeiro.{_R}")
        return

    print(f"\n{_C}── INICIAR CAPTURA ──{_R}")
    iface     = input(f"  Interface  [{_D}enter = todas{_R}]: ").strip() or None
    proto     = input(f"  Protocolo  [{_D}tcp/udp/icmp/arp ou enter{_R}]: ").strip() or None
    filtro_ip = input(f"  Filtrar IP [{_D}enter = todos{_R}]: ").strip() or None
    #OPC8: pergunta filtro BPF tambem no menu interativo
    bpf       = input(f"  Filtro BPF [{_D}ex: 'tcp port 443', enter = nenhum{_R}]: ").strip() or None
    dur_str   = input(f"  Duração    [{_D}segundos, enter = sem limite{_R}]: ").strip()
    live_str  = input(f"  Ver pacotes em tempo real? [{_D}s/N{_R}]: ").strip().lower()

    duracao = int(dur_str) if dur_str.isdigit() else 0
    live    = live_str == "s"

    #reset ao estado global para uma nova sessão
    global start_time
    for k in stats:
        stats[k]["pacotes"] = 0
        stats[k]["bytes"]   = 0
    trafico_capturado.clear()
    for k in hashtable:
        hashtable[k].clear()
    icmp_pending.clear()
    rtt_samples.clear()
    dns_cache.clear()
    scan_tracker.clear()
    icmp_tracker.clear()
    alertas.clear()
    start_time = datetime.datetime.now()

    #args simplificados para reutilizar o process_packet
    class FakeArgs:
        pass
    args         = FakeArgs()
    args.interface = iface
    args.protocol  = proto
    args.ip        = filtro_ip
    args.mac       = None
    args.log       = None
    args.live      = live
    args.duration  = duracao

    _captura_a_correr["flag"] = True

    def _correr():
        def deve_parar(pkt):
            if not _captura_a_correr["flag"]:
                return True
            if duracao > 0:
                elapsed = (datetime.datetime.now() - start_time).total_seconds()
                if elapsed >= duracao:
                    return True
            return False
        try:
            #OPC8: passa o filtro BPF ao scapy
            sniff(iface=iface, prn=lambda p: process_packet(p, args),
                  store=0, stop_filter=deve_parar, filter=bpf)
        except Exception as e:
            print(f"\n  {_RE}[!] Erro na captura: {e}{_R}")
        finally:
            _captura_a_correr["flag"] = False
            print(f"\n  {_G}[✓] Captura terminada.{_R}  (prima Enter para continuar)")

    t = threading.Thread(target=_correr, daemon=True)
    t.start()
    print(f"  {_G}[✓] Captura iniciada{_R}{' (duração: ' + str(duracao) + 's)' if duracao else ''}{' | BPF: ' + bpf if bpf else ''}.")


def _menu_parar_captura():
    if not _captura_a_correr["flag"]:
        print(f"  {_Y}[!] Nenhuma captura em curso.{_R}")
        return
    _captura_a_correr["flag"] = False
    print(f"  {_G}[✓] Sinal de paragem enviado.{_R}")


def _menu_ver_filtros():
    #pede os filtros ao utilizador e chama mostrar_filtrado()
    if not trafico_capturado:
        print(f"  {_Y}[!] Ainda não há pacotes capturados.{_R}")
        return

    print(f"\n{_C}── FILTROS  (Enter = ignorar campo) ──{_R}")

    def _ler(prompt, tipo=str):
        v = input(f"  {prompt}: ").strip()
        if not v:
            return None
        try:
            return tipo(v)
        except ValueError:
            print(f"  {_Y}[!] Valor inválido, campo ignorado.{_R}")
            return None

    proto       = _ler("Protocolo         [TCP/UDP/ICMP/ARP]")
    if proto:
        proto = proto.upper()
    src_ip      = _ler("IP de origem")
    dst_ip      = _ler("IP de destino")
    src_port    = _ler("Porta de origem   [número]", int)
    dst_port    = _ler("Porta de destino  [número]", int)
    tamanho_min = _ler("Tamanho mínimo    [bytes]",  int)
    tamanho_max = _ler("Tamanho máximo    [bytes]",  int)
    hora_inicio = _ler("Hora de início    [HH:MM:SS]")
    hora_fim    = _ler("Hora de fim       [HH:MM:SS]")

    mostrar_filtrado(
        proto=proto, src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        tamanho_min=tamanho_min, tamanho_max=tamanho_max,
        hora_inicio=hora_inicio, hora_fim=hora_fim,
    )


def _menu_guardar():
    if not trafico_capturado:
        print(f"  {_Y}[!] Ainda não há pacotes para guardar.{_R}")
        return
    caminho = input(f"  Nome do ficheiro [{_D}enter = trafico.txt{_R}]: ").strip()
    guardar_trafico_ficheiro(caminho or "trafico.txt")


def exportar_relatorio(caminho="relatorio.txt"):
    #exporta o relatorio completo para um .txt sem codigos de cor ANSI
    if not start_time:
        print(f"  {_Y}[!] Ainda não foi feita nenhuma captura.{_R}")
        return

    total_pkts  = sum(v["pacotes"] for v in stats.values())
    total_bytes = sum(v["bytes"]   for v in stats.values())
    duracao     = datetime.datetime.now() - start_time
    segundos    = duracao.total_seconds()
    agora       = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        with open(caminho, "w", encoding="utf-8") as f:

            #cabeçalho
            f.write("=" * 62 + "\n")
            f.write("  PACKET SNIFFER  ·  RELATÓRIO DE CAPTURA\n")
            f.write(f"  Gerado em : {agora}\n")
            f.write("=" * 62 + "\n\n")

            #resumo geral
            f.write(f"  Duração   : {str(duracao).split('.')[0]}\n")
            f.write(f"  Pacotes   : {total_pkts}\n")
            f.write(f"  Bytes     : {total_bytes} B  ({total_bytes/1024:.2f} KB)\n")
            if segundos > 0:
                f.write(f"  Débito    : {total_bytes/segundos:.1f} B/s\n")
            f.write("\n" + "-" * 62 + "\n")

            #tabela por protocolo
            f.write(f"  {'PROTO':<10} {'PKTS':>6}  {'%':>5}   {'BYTES':>10}  {'%':>5}   DISTRIBUIÇÃO\n")
            f.write("-" * 62 + "\n")

            for proto, dados in sorted(stats.items(), key=lambda x: x[1]["pacotes"], reverse=True):
                if dados["pacotes"] == 0:
                    continue
                pct_pkts  = (dados["pacotes"] / total_pkts  * 100) if total_pkts  > 0 else 0
                pct_bytes = (dados["bytes"]   / total_bytes * 100) if total_bytes > 0 else 0
                filled    = int(pct_pkts / 5)
                barra     = "#" * filled + "." * (20 - filled)  #ASCII puro
                f.write(
                    f"  {proto:<10} {dados['pacotes']:>6}  {pct_pkts:>4.1f}%"
                    f"   {dados['bytes']:>10}  {pct_bytes:>4.1f}%   {barra}\n"
                )

            #RTT ICMP
            if rtt_samples:
                f.write("\n" + "-" * 62 + "\n")
                f.write("  RTT MÉDIO (ICMP)\n")
                f.write(f"  amostras  : {len(rtt_samples)}\n")
                f.write(f"  mínimo    : {min(rtt_samples):.2f} ms\n")
                f.write(f"  máximo    : {max(rtt_samples):.2f} ms\n")
                f.write(f"  média     : {sum(rtt_samples)/len(rtt_samples):.2f} ms\n")

            #alertas de segurança
            if alertas:
                f.write("\n" + "-" * 62 + "\n")
                f.write("  ALERTAS DE SEGURANÇA DETETADOS\n")
                for a in alertas:
                    f.write(f"  {a}\n")

            #top hostnames
            if dns_cache:
                hostname_counts = {}
                for ip, hostname in dns_cache.items():
                    if hostname != ip:
                        hostname_counts[hostname] = hostname_counts.get(hostname, 0) + 1
                if hostname_counts:
                    top = sorted(hostname_counts.items(), key=lambda x: x[1], reverse=True)[:5]
                    f.write("\n" + "-" * 62 + "\n")
                    f.write("  TOP HOSTNAMES RESOLVIDOS\n")
                    for hostname, _ in top:
                        f.write(f"  -> {hostname}\n")

            f.write("\n" + "=" * 62 + "\n")

        print(f"  {_G}[✓] Relatório exportado para '{caminho}'{_R}")

    except OSError as e:
        print(f"  {_RE}[!] Erro ao escrever ficheiro: {e}{_R}")


def _menu_exportar_relatorio():
    if not start_time:
        print(f"  {_Y}[!] Ainda não foi feita nenhuma captura.{_R}")
        return
    caminho = input(f"  Nome do ficheiro [{_D}enter = relatorio.txt{_R}]: ").strip()
    exportar_relatorio(caminho or "relatorio.txt")


def menu():
    #loop principal do menu interativo
    opcoes = {
        "1": ("Iniciar captura",               _menu_iniciar_captura),
        "2": ("Parar captura",                 _menu_parar_captura),
        "3": ("Ver tráfego com filtros",       _menu_ver_filtros),
        "4": ("Guardar tráfego em .txt",       _menu_guardar),
        "5": ("Ver estatísticas",              print_stats),
        "6": ("Exportar relatório para .txt",  _menu_exportar_relatorio),
        "0": ("Sair",                          None),
    }

    while True:
        _cabecalho_menu()
        for key, (descricao, _) in opcoes.items():
            cor = _RE if key == "0" else _W
            print(f"  {_B}{_C}[{key}]{_R}  {cor}{descricao}{_R}")
        print()

        escolha = input(f"  {_B}Opção:{_R} ").strip()

        if escolha not in opcoes:
            print(f"  {_Y}[!] Opção inválida.{_R}")
            continue

        descricao, acao = opcoes[escolha]

        if escolha == "0":
            if _captura_a_correr["flag"]:
                _captura_a_correr["flag"] = False
                print(f"  {_Y}[→] A parar captura antes de sair...{_R}")
            print(f"\n  {_G}Até logo!{_R}\n")
            break

        print(f"\n{_D}── {descricao} ──{_R}")
        acao()
        input(f"\n  {_D}[Enter para continuar]{_R}")


if __name__ == "__main__":
    import sys
    #se foram passados argumentos usa o modo linha de comandos
    #caso contrario abre o menu interativo
    if len(sys.argv) > 1:
        main()
    else:
        menu()