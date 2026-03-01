# Aegis Endpoint Defense 🛡️

[Português](#português) | [English](#english)

---

## Português

Aegis é uma plataforma robusta de **SIEM & EDR (Endpoint Detection and Response)** projetada para monitoramento em tempo real, detecção proativa de ameaças e resposta automatizada (SOAR) em ambientes Windows. Com uma interface moderna "Hyper-Glass", o Aegis oferece visibilidade total e controle granular sobre seus endpoints.

### 🚀 Funcionalidades SOC & EDR
- **Dashboard em Tempo Real**: Visão holística de todos os agentes online/offline com métricas de saúde do ambiente.
- **Aegis Forensic — Visão Detalhada**: 
    - Sincronização em tempo real de status e metadados.
    - Captura de tela remota para evidência visual instantânea.
    - Lista dinâmica de processos, serviços e conexões de rede operacionais.
- **Capacidades SOAR & Reparo**:
    - **Diagnóstico do Sistema**: Atalhos para `SFC /scannow` e reparo de imagem com `DISM`.
    - **Manutenção de Rede**: Reset de Winsock, Flush DNS e renovação de IP com um clique.
    - **Forense Digital**: Coleta de Event Logs (SIEM), Dump de arquivos temporários e análise de processos por CPU.
- **Contenção de Ameaças**:
    - **Host Isolation**: Isolamento imediato via Firewall (bloqueia todo tráfego exceto com o C2).
    - **Wipe Remoto**: Desinstalação forçada e auto-remoção do agente em caso de comprometimento total.
- **Aegis AI Copilot**: Assistente de IA integrado com contexto total do agente para auxiliar na triagem de incidentes.

### 🛠️ Instalação do Servidor C2

#### 🐳 Via Docker (Produção)
A forma mais rápida e segura de rodar o Aegis no seu servidor VPS.
```bash
docker-compose up -d --build
```
O painel estará disponível em `http://82.112.245.99:5000` (substitua pelo IP do seu servidor).

#### 🏗️ Manual (Desenvolvimento)
1. Instale os requisitos: `pip install -r requirements.txt`
2. Configure as credenciais: Use o `.env.example` para criar seu arquivo `.env`.
3. Inicie o servidor: `python server/app.py`

### 💻 Compilação do Agente
O agente Aegis deve ser compilado como um executável furtivo para Windows.
1. Navegue até a pasta do agente: `cd agent`
2. Compile o MSI/EXE: `python setup.py build`
3. Os binários estarão na pasta `build/` ou `dist/`.

> [!IMPORTANT]
> O arquivo `.env` nunca deve ser enviado para o Git. Use o `.env.example` como guia.

---

## English

Aegis is a robust **SIEM & EDR (Endpoint Detection and Response)** platform designed for real-time monitoring, proactive threat detection, and automated orchestration (SOAR) in Windows environments. Featuring a modern "Hyper-Glass" UI, Aegis provides full visibility and granular control over your endpoints.

### 🚀 SOC & EDR Features
- **Real-Time Dashboard**: Holistic view of all online/offline agents with environment health metrics.
- **Aegis Forensic — Detailed View**:
    - Real-time synchronization of status and metadata.
    - Remote screenshot capture for instant visual evidence.
    - Dynamic lists of processes, services, and live network connections.
- **SOAR & Repair Capabilities**:
    - **System Diagnostics**: Shortcuts for `SFC /scannow` and image repair via `DISM`.
    - **Network Maintenance**: One-click Winsock reset, DNS Flush, and IP renewal.
    - **Digital Forensics**: Event Log collection (SIEM), temporary file dumping, and CPU-based process analysis.
- **Threat Containment**:
    - **Host Isolation**: Immediate firewall-based isolation (blocks all traffic except C2 communication).
    - **Remote Wipe**: Forced uninstallation and self-removal in case of total compromise.
- **Aegis AI Copilot**: Integrated AI assistant with full agent context to assist in incident triage.

### 🛠️ C2 Server Installation

#### 🐳 Via Docker (Production)
The fastest and most secure way to run Aegis on your VPS.
```bash
docker-compose up -d --build
```
The dashboard will be available at `http://82.112.245.99:5000` (replace with your server IP).

#### 🏗️ Manual (Development)
1. Install requirements: `pip install -r requirements.txt`
2. Setup Credentials: Use `.env.example` to create your `.env` file.
3. Start Server: `python server/app.py`

### 💻 Agent Compilation
The Aegis agent should be compiled as a stealth Windows executable.
1. Navigate to agent folder: `cd agent`
2. Build MSI/EXE: `python setup.py build`
3. Binaries will be available in `build/` or `dist/` folders.

> [!IMPORTANT]
> The `.env` file must never be committed to Git. Always use `.env.example` as a template for keys and credentials.
