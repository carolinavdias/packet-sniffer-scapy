<div align="center">

# 🌐 ᑭᗩᑕKET ᔕᑎIᖴᖴEᖇ

### Trabalho Prático Nº2 - Redes de Computadores
**Universidade do Minho · LEI · 2025/2026**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.x-green?style=for-the-badge)
![License](https://img.shields.io/badge/Licença-Académica-orange?style=for-the-badge)
![Opcionais](https://img.shields.io/badge/Opcionais%20Implementados-11-purple?style=for-the-badge)

**Grupo 45 · PL4**

[Ana Patrícia da Silva Machado](mailto:a111661@alunos.uminho.pt) · `a111661`  
[Carolina Francisca Vieira Dias](mailto:a111179@alunos.uminho.pt) · `a111179`  
[Rúben João Mendes Oliveira](mailto:a93625@alunos.uminho.pt) · `a93625`

</div>

## Visão Geral

Ferramenta de análise de tráfego de rede em Python com Scapy. Captura e classifica pacotes em tempo real (ARP, ICMP, TCP, UDP) a partir de qualquer interface física ou emulada, com 11 funcionalidades opcionais implementadas.

```
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

## Requisitos e Instalação

```bash
# Clonar o repositório
git clone https://github.com/rubCoder/RC---TP2---PL4.git
cd RC---TP2---PL4

# Instalar Scapy (obrigatório)
sudo pip3 install scapy --break-system-packages

# Instalar matplotlib (opcional — só necessário para --graph)
pip install matplotlib --break-system-packages
```

> ⚠️ A captura em interface real requer permissões de administrador (`sudo`).

---

## Como Usar

**Menu interativo** (sem argumentos):
```bash
sudo python3 sniffer.py
```

**Linha de comandos:**
```bash
sudo python3 sniffer.py -i wlp2s0 --live -l captura.txt
sudo python3 sniffer.py -i eth0 --live --bpf 'tcp port 443' --duration 60 --graph
sudo python3 sniffer.py -i wlp2s0 --duration 30 --fproto TCP --fdport 443
```

---

## Parâmetros

| Parâmetro | Exemplo | Descrição |
|---|---|---|
| `-i` | `-i eth0` | Interface de rede |
| `-p` | `-p tcp` | Filtro por protocolo (`arp`, `icmp`, `tcp`, `udp`) |
| `--ip` | `--ip 192.168.1.1` | Filtro por endereço IP |
| `--mac` | `--mac aa:bb:...` | Filtro por endereço MAC |
| `-l` | `-l captura.txt` | Modo log (ficheiro de saída) |
| `--live` | `--live` | Output em tempo real na consola |
| `--bpf` | `--bpf 'tcp port 443'` | Expressão BPF estilo tcpdump |
| `--duration` | `--duration 60` | Duração máxima em segundos |
| `--save` | `--save sessao.txt` | Exporta relatório consolidado |
| `--graph` | `--graph` | Gera gráfico de distribuição |
| `--fproto` / `--fsrc` / `--fdst` | `--fproto TCP` | Filtros pós-captura sobre hashtable O(1) |
| `--fsport` / `--fdport` / `--fmin` / `--fmax` / `--fhi` / `--fhf` | `--fdport 443` | Filtros adicionais pós-captura |

---

## 📁 Estrutura do Projeto

```
RC---TP2---PL4/
├── sniffer.py                # Sniffer principal
├── sniffer_dashboard.html    # Dashboard web interativo (Opcional 11)
├── RC-TP2-PL4.pdf            # Relatório do projeto
└── README.md                 # Este ficheiro
```

---

<div align="center">

Desenvolvido para a UC de Redes de Computadores · UMinho 2026

</div>
