<div align="center">

# 🌐 Packet Sniffer

### Trabalho Prático Nº2 — Redes de Computadores
**Universidade do Minho · LEI · 2025/2026**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.x-green?style=for-the-badge)
![License](https://img.shields.io/badge/Licença-Académica-orange?style=for-the-badge)
![Lines](https://img.shields.io/badge/Linhas%20de%20Código-1006-purple?style=for-the-badge)
![Opcionais](https://img.shields.io/badge/Opcionais%20Implementados-11-red?style=for-the-badge)

**Grupo 45 · PL4**

[Ana Patrícia da Silva Machado](mailto:a111661@alunos.uminho.pt) · `a111661`  
[Carolina Francisca Vieira Dias](mailto:a111179@alunos.uminho.pt) · `a111179`  
[Rúben João Mendes Oliveira](mailto:a93625@alunos.uminho.pt) · `a93625`

</div>

---

## 📋 Índice

- [Visão Geral](#-visão-geral)
- [Funcionalidades Base](#-funcionalidades-base)
- [Funcionalidades Opcionais](#-funcionalidades-opcionais-11)
- [Requisitos](#-requisitos)
- [Instalação](#-instalação)
- [Como Usar](#-como-usar)
  - [Menu Interativo](#menu-interativo)
  - [Linha de Comandos](#linha-de-comandos)
  - [Parâmetros](#parâmetros)
  - [Filtros Pós-Captura](#filtros-pós-captura)
- [Exemplos de Uso](#-exemplos-de-uso)
- [Arquitetura](#-arquitetura)
- [Estrutura do Projeto](#-estrutura-do-projeto)

---

## 🔍 Visão Geral

O **Packet Sniffer** é uma ferramenta de análise de tráfego de rede desenvolvida em Python com a biblioteca Scapy. Captura e analisa pacotes em tempo real a partir de qualquer interface de rede — física ou emulada (CORE) — identificando e classificando protocolos das camadas L2 a L4.

O sniffer suporta dois modos de execução:
- **Menu interativo** — acessível sem argumentos, com threading para captura em segundo plano
- **Linha de comandos** — para integração em scripts e automatização

```
A capturar em wlp2s0... (Ctrl+C para parar)

══════════════════════════════════════════════════════════════
  >>>  PACKET SNIFFER  ·  RELATÓRIO DE CAPTURA  <<<
══════════════════════════════════════════════════════════════
  【 duração   0:02:14
  【 pacotes   674
  【 bytes     210681 B  (205.74 KB)
  【 débito    3162.9 B/s
──────────────────────────────────────────────────────────────
  PROTO       PKTS     %        BYTES     %   DISTRIBUIÇÃO
──────────────────────────────────────────────────────────────
  TCP          341  50.6%      100915  47.9%   ████████░░░░░░░░░░░░
  UDP          215  31.9%       98202  46.6%   ██████░░░░░░░░░░░░░░
  ICMP         118  17.5%       11564   5.5%   ███░░░░░░░░░░░░░░░░░
```

---

## ✅ Funcionalidades Base

| Funcionalidade | Descrição |
|---|---|
| **Captura em tempo real** | Interface física ou emulada, modo promíscuo |
| **Parsing L2–L4** | ARP, ICMP, TCP, UDP com extração de campos relevantes |
| **Filtros de captura** | Por protocolo, IP de origem/destino, endereço MAC |
| **Modo Live** | Output formatado com cores ANSI em tempo real |
| **Modo Log** | Escrita incremental para ficheiro `.txt` |
| **Exportação consolidada** | Relatório completo com `--save` no final da sessão |
| **Filtros BPF nativos** | Expressões estilo tcpdump ao nível do kernel |

---

## 🚀 Funcionalidades Opcionais (11)

| # | Opcional | Comando/Trigger |
|---|---|---|
| 1 | **Estatísticas finais coloridas** com distribuição por protocolo | `Ctrl+C` ou `--duration` |
| 2 | **Cálculo de RTT médio** via correlação de pares ICMP echo | Automático |
| 3 | **Visualização gráfica** de pacotes e bytes por protocolo | `--graph` |
| 4 | **Resolução automática de hostnames** com cache interna | Automático |
| 5 | **Deteção de anomalias** — port scan (≥15 portas) e ICMP flood (>20/s) | Automático |
| 6 | **Duração limitada** com término automático | `--duration N` |
| 7 | **Identificação de serviços por porta** (23 portas IANA) | Automático |
| 8 | **Filtros BPF nativos ao nível do kernel** | `--bpf` |
| 9 | **Menu interativo** com threading e estado em tempo real | Sem argumentos |
| 10 | **Hashtable indexada** para filtragem pós-captura O(1) | `--fproto`, `--fdst`, ... |
| 11 | **Dashboard web** HTML/CSS/JS interativo | `sniffer_dashboard.html` |

---

## 📦 Requisitos

- **Python 3.8+**
- **Scapy** (obrigatório)
- **matplotlib** (opcional — apenas para `--graph`)
- Permissões de administrador para captura em interface real

---

## 🔧 Instalação

**1. Clonar o repositório**
```bash
git clone https://github.com/rubCoder/RC---TP2---PL4.git
cd RC---TP2---PL4
```

**2. Instalar a Scapy**
```bash
sudo pip3 install scapy --break-system-packages
```

**3. Instalar o matplotlib** *(opcional — necessário para `--graph`)*
```bash
pip install matplotlib --break-system-packages
```

---

## 💻 Como Usar

### Menu Interativo

Executar sem argumentos abre o menu interativo. A captura corre numa thread independente, permitindo interação contínua com o menu.

```bash
sudo python3 sniffer.py
```

```
══════════════════════════════════════════════
   PACKET SNIFFER  ·  MENU PRINCIPAL
──────────────────────────────────────────────
  estado   : parada
  pacotes  : 0
══════════════════════════════════════════════
  [1]  Iniciar captura
  [2]  Parar captura
  [3]  Ver tráfego com filtros
  [4]  Guardar tráfego em .txt
  [5]  Ver estatísticas
  [6]  Exportar relatório para .txt
  [0]  Sair
```

---

### Linha de Comandos

```bash
sudo python3 sniffer.py [opções]
```

---

### Parâmetros

| Parâmetro | Exemplo | Descrição |
|---|---|---|
| `-i`, `--interface` | `-i eth0` | Interface de rede a capturar |
| `-p`, `--protocol` | `-p tcp` | Filtro por protocolo (`arp`, `icmp`, `tcp`, `udp`) |
| `--ip` | `--ip 192.168.1.1` | Filtro por endereço IP de origem ou destino |
| `--mac` | `--mac aa:bb:cc:dd:ee:ff` | Filtro por endereço MAC |
| `-l`, `--log` | `-l captura.txt` | Ativa modo log e define ficheiro de saída |
| `--live` | `--live` | Ativa output em tempo real na consola |
| `--graph` | `--graph` | Gera gráfico de distribuição no final |
| `--duration` | `--duration 60` | Para automaticamente após N segundos |
| `--save` | `--save sessao.txt` | Exporta relatório consolidado no final |
| `--bpf` | `--bpf 'tcp port 443'` | Expressão BPF estilo tcpdump ao nível do kernel |

---

### Filtros Pós-Captura

Aplicados sobre a hashtable indexada após a captura, com complexidade O(1).

| Parâmetro | Exemplo | Descrição |
|---|---|---|
| `--fproto` | `--fproto TCP` | Filtrar por protocolo |
| `--fsrc` | `--fsrc 192.168.1.5` | Filtrar por IP de origem |
| `--fdst` | `--fdst 8.8.8.8` | Filtrar por IP de destino |
| `--fsport` | `--fsport 52341` | Filtrar por porta de origem |
| `--fdport` | `--fdport 443` | Filtrar por porta de destino |
| `--fmin` | `--fmin 500` | Tamanho mínimo em bytes |
| `--fmax` | `--fmax 1500` | Tamanho máximo em bytes |
| `--fhi` | `--fhi 10:00:00` | Hora de início do intervalo |
| `--fhf` | `--fhf 10:05:00` | Hora de fim do intervalo |

---

## 💡 Exemplos de Uso

**Captura básica em modo live com log:**
```bash
sudo python3 sniffer.py -i wlp2s0 --live -l captura.txt
```

**Captura de 60 segundos com gráfico no final:**
```bash
sudo python3 sniffer.py -i eth0 --live --duration 60 --graph
```

**Filtrar apenas tráfego HTTPS com BPF:**
```bash
sudo python3 sniffer.py -i wlp2s0 --live --bpf 'tcp port 443'
```

**Captura com exportação consolidada:**
```bash
sudo python3 sniffer.py -i wlp2s0 --live --save relatorio_final.txt
```

**Filtrar pós-captura — só TCP na porta 443:**
```bash
sudo python3 sniffer.py -i wlp2s0 --duration 30 --fproto TCP --fdport 443
```

**Combinar BPF + duração + save:**
```bash
sudo python3 sniffer.py -i eth0 --live --bpf 'icmp or arp' --duration 120 --save icmp_arp.txt
```

**Simular e detetar port scan:**
```bash
# Terminal 1 — sniffer
sudo python3 sniffer.py -i lo --live

# Terminal 2 — simular scan
for port in $(seq 1 30); do nc -zv -w1 localhost $port 2>/dev/null; done
```

---

## 🏗️ Arquitetura

O sniffer opera através de um pipeline de 9 etapas:

```
 ┌─────────────────────────────────────────────────────┐
 │  1. Inicialização  →  CLI args ou Menu interativo   │
 │  2. Configuração   →  interface, BPF, modos saída   │
 │  3. Escuta         →  sniff() modo promíscuo        │
 │  4. Análise        →  process_packet() por frame    │
 │  5. Enriquecimento →  hostname + porta + RTT        │
 │  6. Anomalias      →  port scan + ICMP flood        │
 │  7. Saída          →  live console e/ou ficheiro    │
 │  8. Ciclo          →  até Ctrl+C ou --duration      │
 │  9. Relatório      →  stats + alertas + gráfico     │
 └─────────────────────────────────────────────────────┘
```

**Componentes principais do `sniffer.py`:**

| Componente | Função |
|---|---|
| `process_packet()` | Núcleo — parsing L2–L4, enriquecimento, indexação |
| `filtrar_hashtable()` | Filtragem pós-captura O(1) por interseção de buckets |
| `verificar_anomalias()` | Deteção de port scan e ICMP flood em tempo real |
| `resolver_hostname()` | DNS resolver com cache para evitar latência repetida |
| `print_stats()` | Relatório final colorido com ANSI |
| `plot_stats()` | Gráfico matplotlib (dependência opcional) |
| `menu()` | Loop do menu interativo com threading |

---

## 📁 Estrutura do Projeto

```
RC---TP2---PL4/
├── sniffer.py                # Sniffer principal (1006 linhas)
├── sniffer_dashboard.html    # Dashboard web interativo (Opcional 11)
├── RC-TP2-PL4.pdf            # Relatório do projeto
└── README.md                 # Este ficheiro
```

---

<div align="center">

Desenvolvido com 🔬 para a UC de Redes de Computadores · UMinho 2026

</div>
