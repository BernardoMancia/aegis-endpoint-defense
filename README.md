# Aegis Endpoint Defense 🛡️
[![Aegis Build](https://img.shields.io/badge/Aegis-v1.0.0--Stable-0ea5e9?style=for-the-badge&logo=shippable)](https://github.com/BernardoMancia/aegis-endpoint-defense)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Android-white?style=for-the-badge&logo=windows)](https://github.com/BernardoMancia/aegis-endpoint-defense)
[![C2 Status](https://img.shields.io/badge/C2_Server-82.112.245.99-emerald?style=for-the-badge&logo=linux)](http://82.112.245.99:5000)

[Português](#português) | [English](#english)

---

## Português

Aegis é uma plataforma avançada de **SIEM & EDR (Endpoint Detection and Response)** de código aberto, projetada para fornecer visibilidade total, proteção proativa e resposta automatizada contra ameaças em larga escala. Com uma arquitetura focada em **Furtividade (Stealth)** e **Forense Digital**, o Aegis é a sentinela definitiva para seus endpoints.

### 🛡️ Engenharia de Furtividade & Proteção
- **Silent Execution**: O agente Windows opera sem janelas (`CREATE_NO_WINDOW`), garantindo que processos de defesa e coleta de evidências rodem de forma invisível.
- **Resiliência a Travamentos**: Gerenciamento agressivo de *file locks* com `psutil`, permitindo manipulação de arquivos críticos e desinstalação limpa via scripts temporários em `%TEMP%`.
- **Política de Soft Delete**: Dados de agentes não são apagados fisicamente do banco de dados (SQLite/SQLAlchemy). O Aegis usa estados lógicos (`is_uninstalled=True`), preservando o histórico para análise forense e trilhas de auditoria do SIEM.

### 🚀 Capacidades SOC & SOAR
- **Hyper-Glass Forensic UI**: Dashboard responsivo com sincronização em tempo real (polling de 3s) de status, screenshots e metadados.
- **Exploração Forense**: Lista dinâmica de processos, conexões de rede ativas e serviços do sistema.
- **Ações de Resposta (SOAR)**:
    - **Host Isolation**: Isolamento imediato via Firewall do Windows (regra Zero-Trust).
    - **System Repair**: Atalhos para reparo de integridade (`SFC /scannow`) e imagem (`DISM`).
    - **Remediação de Rede**: Reset de stack Winsock e DNS Flush centralizado.
- **IA Integrada**: Copilot de segurança com contexto total do endpoint para triagem acelerada.

### ⚙️ Infraestrutura C2 (Centrífuga)
O servidor central está hospedado em: **`82.112.245.99`**
- **Porta Padrão**: `5000` (Dashboard / API)
- **Deploy**: Recomendado via Docker para isolamento e escalabilidade.

---

## English

Aegis is an advanced open-source **SIEM & EDR (Endpoint Detection and Response)** platform, designed to provide total visibility, proactive protection, and automated threat response at scale. Built with a core focus on **Stealth Engineering** and **Digital Forensics**, Aegis is the ultimate sentinel for your endpoints.

### 🛡️ Stealth Engineering & Protection
- **Silent Execution**: The Windows agent operates entirely without console windows (`CREATE_NO_WINDOW`), ensuring defense and evidence collection processes run invisibly to the end-user.
- **Process Resilience**: Aggressive *file lock* management using `psutil`, enabling manipulation of critical files and clean uninstallation via temporary scripts in `%TEMP%`.
- **Soft Delete Policy**: Agent data is never physically purged from the database (SQLite/SQLAlchemy). Aegis utilizes logical states (`is_uninstalled=True`), preserving historical data for forensic analysis and SIEM audit trails.

### 🚀 SOC & SOAR Capabilities
- **Hyper-Glass Forensic UI**: Responsive dashboard with real-time synchronization (3s polling) for status, screenshots, and metadata.
- **Forensic Exploration**: Dynamic lists of processes, active network connections, and system services.
- **Response Actions (SOAR)**:
    - **Host Isolation**: Immediate isolation via Windows Firewall (Zero-Trust policy).
    - **System Repair**: Shortcuts for integrity repair (`SFC /scannow`) and image restoration (`DISM`).
    - **Network Remediation**: Centralized Winsock stack reset and DNS Flush.
- **Integrated AI**: Security Copilot with full endpoint context for accelerated incident triage.

### ⚙️ C2 Infrastructure (Centrifuge)
The official central server is hosted at: **`82.112.245.99`**
- **Default Port**: `5000` (Dashboard / API)
- **Deployment**: Docker-based deployment is highly recommended for security and scalability.

---

### 🛠️ Quick Start / Início Rápido

**1. Clone & Configure:**
```bash
git clone https://github.com/BernardoMancia/aegis-endpoint-defense.git
cp .env.example .env # NUNCA envie o .env para o Git / NEVER commit .env
```

**2. Deploy Server (Docker):**
```bash
docker-compose up -d --build
```

**3. Build Agent (Windows):**
```bash
cd agent
python setup.py build
# Binaries ready in build/dist folders
```
