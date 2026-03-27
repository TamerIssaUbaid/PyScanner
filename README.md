# PyScanner 🔍

> Port scanner educacional inspirado no nmap, desenvolvido em Python puro para fins de auditoria e segurança da informação.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Security](https://img.shields.io/badge/Topic-Cybersecurity-red?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## 📌 Sobre o projeto

O **PyScanner** é uma ferramenta de reconhecimento de rede desenvolvida do zero em Python, sem dependências externas. Permite identificar portas abertas em um host-alvo, capturar banners de serviços, estimar o sistema operacional via TTL e gerar alertas de risco automáticos para portas críticas.

Desenvolvido como projeto prático da disciplina de **Segurança da Informação**, com foco em técnicas reais usadas em auditorias e operações de SOC (Security Operations Center).

> **MITRE ATT&CK:** Este projeto simula a técnica [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/), utilizada por adversários para mapear serviços ativos em uma rede.

---

## ⚙️ Funcionalidades

- ✅ Scan TCP (connect scan) e UDP
- ✅ Threads paralelas para alta performance
- ✅ Banner grabbing em portas comuns (SSH, FTP, HTTP, SMTP...)
- ✅ Fingerprinting de SO baseado em TTL (ping)
- ✅ Análise de risco automática por porta (`CRÍTICA`, `ALTA`, `MÉDIA`)
- ✅ Exportação de relatório em JSON
- ✅ Suporte a hostname e IP
- ✅ Sem dependências externas — apenas biblioteca padrão do Python

---

## 🚀 Como usar

### Pré-requisitos

- Python 3.8 ou superior
- Nenhuma instalação adicional necessária

### Instalação

```bash
git clone https://github.com/TamerIssaUbaid/PyScanner.git
cd PyScanner
```

### Execução

```bash
# Scan básico (top 100 portas mais comuns)
python scanner.py 192.168.1.1

# Portas específicas
python scanner.py 192.168.1.1 -p 22,80,443

# Range de portas
python scanner.py 192.168.1.1 -p 1-1000

# Top ~1000 portas conhecidas
python scanner.py 192.168.1.1 --top

# Scan em hostname
python scanner.py meusite.com.br -p 80,443,8080

# Scan rápido com mais threads
python scanner.py 192.168.1.1 -p 1-65535 --threads 500 --timeout 0.5

# Scan UDP
python scanner.py 192.168.1.1 --udp -p 53,161,500

# Salvar relatório JSON
python scanner.py 192.168.1.1 -p 1-1000 -o resultado.json

# Modo verbose (exibe também portas fechadas)
python scanner.py 192.168.1.1 -p 1-100 -v
```

---

## 🏳️ Flags disponíveis

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `-p` / `--ports` | top 100 | Portas alvo: `80` \| `80,443` \| `1-1000` \| `22,80-100,443` |
| `--top` | off | Escaneia ~1000 portas conhecidas predefinidas |
| `--udp` | off (TCP) | Usa UDP em vez de TCP |
| `--threads` | 100 | Número de threads paralelas |
| `--timeout` | 1.0 | Timeout por porta em segundos |
| `--no-banner` | off | Desabilita banner grabbing (scan mais rápido) |
| `-o` / `--output` | nenhum | Caminho para salvar relatório JSON |
| `-v` / `--verbose` | off | Exibe também portas fechadas |

---

## 📊 Análise de risco por porta

O scanner identifica automaticamente portas de alto risco e exibe alertas coloridos no terminal:

| Nível | Porta | Motivo |
|-------|-------|--------|
| 🔴 CRÍTICA | 23 (Telnet) | Transmite tudo em texto claro |
| 🔴 CRÍTICA | 445 (SMB) | Vetor do WannaCry / EternalBlue |
| 🔴 CRÍTICA | 4444 | Porta padrão do Metasploit — possível backdoor |
| 🔴 CRÍTICA | 6379 (Redis) | Sem autenticação = execução remota de comandos |
| 🟡 ALTA | 21 (FTP) | Credenciais em texto claro |
| 🟡 ALTA | 3306 (MySQL) | Banco de dados exposto na internet |
| 🟡 ALTA | 3389 (RDP) | Principal vetor de ransomware |
| 🟡 ALTA | 5900 (VNC) | Desktop remoto sem criptografia |
| 🔵 MÉDIA | 22 (SSH) | Vulnerável a brute-force |
| 🔵 MÉDIA | 53 (DNS) | Alvo de amplificação DDoS |

---

## 📄 Formato do relatório JSON

```json
{
  "meta": {
    "target": "192.168.1.1",
    "ip": "192.168.1.1",
    "hostname": "router.local",
    "protocol": "tcp",
    "ports_scanned": 1000,
    "open_ports": 3,
    "start": "2025-08-01T14:32:00",
    "duration_s": 12.45
  },
  "results": [
    {
      "port": 22,
      "state": "open",
      "proto": "tcp",
      "service": "SSH",
      "banner": "SSH-2.0-OpenSSH_8.9p1"
    }
  ]
}
```

---

## 🛠️ Tecnologias e conceitos aplicados

| Tecnologia | Uso |
|------------|-----|
| `socket` | Conexões TCP/UDP e resolução DNS |
| `concurrent.futures.ThreadPoolExecutor` | Paralelismo para scan de múltiplas portas simultaneamente |
| `argparse` | Interface de linha de comando (CLI) |
| `json` | Geração de relatórios estruturados |
| Banner Grabbing | Captura de cabeçalhos de serviços para identificação de versões |
| TTL Fingerprinting | Estimativa do sistema operacional via tempo de vida do pacote ICMP |

---

## 📁 Estrutura do projeto

```
PyScanner/
├── scanner.py      # Script principal
└── README.md       # Documentação
```

---

## ⚠️ Aviso Legal

Este projeto foi desenvolvido **exclusivamente para fins educacionais** e de auditoria em ambientes controlados.

> **Use apenas em redes e sistemas que você possui ou tem autorização expressa para testar.**
> O uso não autorizado desta ferramenta pode violar leis de crimes cibernéticos, incluindo a **Lei 12.737/2012 (Lei Carolina Dieckmann)** e o **Art. 154-A do Código Penal Brasileiro**.
> O autor não se responsabiliza pelo uso indevido desta ferramenta.

---

## 👤 Autor

**Támer Issa Ubaid**
- GitHub: [@TamerIssaUbaid](https://github.com/TamerIssaUbaid)

---

## 📜 Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.
