# Aegis EDR: Distributed Endpoint Telemetry & Remediation Framework

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Flask](https://img.shields.io/badge/Framework-Flask-green)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey)

**[English Documentation]** | [Documentação em Português](#documentação-técnica-pt-br)

---

## Abstract

Aegis EDR is a lightweight, scalable security orchestration framework designed to provide real-time visibility into distributed endpoint infrastructure. Built upon a modular Client-Server architecture, the system facilitates granular resource monitoring, security posture assessment (AV heuristics), and rapid incident response through remote command execution.

---

## System Architecture

The solution operates on a strict **C2 (Command and Control)** topology, utilizing RESTful API endpoints for asynchronous communication between the Central Orchestrator (VPS) and distributed Sensors (Endpoints).

### 1. The Orchestrator (Server-Side)

- **Core:** Python Flask micro-framework served via WSGI
- **Persistence:** SQLAlchemy ORM
- **Security:**
  - Request sanitization (SQL Injection mitigation)
  - PBKDF2 (SHA-256) password hashing for operator authentication
  - CSRF protection

### 2. The Sensor (Client-Side)

- **Runtime:** Native Python execution tailored for Windows 10/11
- **Data Acquisition:** WMI (Windows Management Instrumentation) queries for antivirus enumeration and heuristics
- **Resilience:** Exception-handled main loops with jitter-based reporting
- **AI Integration:** Optional external LLM APIs (OpenAI) for log enrichment and heuristic analysis

---

## Deployment & Configuration

### Prerequisites

- **Orchestrator:** Linux (Ubuntu/Debian recommended) with Python 3.10+
- **Sensor:** Windows 10/11

### Installation Guide

#### A. Orchestrator Deployment (Linux)

```bash
git clone https://github.com/BernardoMancia/aegis-endpoint-defense.git
cd aegis-endpoint-defense/server_vps

pip install -r requirements.txt

python manage_users.py add

python app.py
```

#### B. Sensor Deployment (Windows)

1. Navigate to `client_windows/agent_gui.py`
2. Configure the `SERVER_IP` constant with your VPS IP address
3. Execute the agent:

```powershell
pip install -r requirements.txt
python agent_gui.py
```

---

## Capabilities Matrix

| Feature | Description | Technical Implementation |
|---|---|---|
| Telemetry Ingestion | Real-time CPU/RAM usage metrics | `psutil` sampling |
| Asset Identification | Hostname resolution & IP tracking | `socket` libraries |
| Security Posture | Antivirus detection & status verification | WMI `root\SecurityCenter2` |
| Remote Remediation | Host reboot & rename actions | PowerShell/CMD via subprocess |
| Audit Trail | Immutable logging of security alerts | Database transaction journaling |

---

## Documentação Técnica (PT-BR)

Aegis EDR é um framework de orquestração de segurança focado em visibilidade de endpoints e resposta a incidentes. O projeto demonstra a aplicação de arquiteturas distribuídas para coleta de telemetria e execução remota de comandos em ambientes corporativos simulados.

### Especificações Técnicas

O sistema foi desenvolvido priorizando a modularidade e a segurança no transporte de dados. A comunicação entre os Agentes (Windows) e o Orquestrador (Linux VPS) ocorre via HTTP/JSON, garantindo interoperabilidade e facilidade de inspeção de tráfego.

### Funcionalidades Chave

- **Monitoramento de Recursos:** coleta contínua de métricas de desempenho para detecção de anomalias (ex.: picos de CPU indicando cryptojacking).
- **Auditoria de Segurança:** verificação ativa do namespace WMI para garantir que soluções de antivírus estejam ativas.
- **Resposta a Incidentes:** capacidade de interrupção forçada (reboot) e reconfiguração de identidade (rename) de máquinas comprometidas.
- **Gestão de Acesso:** interface administrativa protegida por hashing criptográfico robusto.

---

## Aviso Legal / Disclaimer

Este software é um projeto independente desenvolvido para fins educacionais e de pesquisa em Engenharia de Software e Segurança da Informação.
