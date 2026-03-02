# Aegis Endpoint Defense 🛡️
[![Aegis Build](https://img.shields.io/badge/Aegis-v1.2.0--Stable-0ea5e9?style=for-the-badge&logo=shippable)](https://github.com/BernardoMancia/aegis-endpoint-defense)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Android-white?style=for-the-badge&logo=windows)](https://github.com/BernardoMancia/aegis-endpoint-defense)
[![C2 Status](https://img.shields.io/badge/C2_Network-Operational-emerald?style=for-the-badge&logo=linux)](https://github.com/BernardoMancia/aegis-endpoint-defense)

[Português](#português) | [English](#english)

---

## Português

Aegis é uma plataforma avançada de **Next-Gen EDR (Endpoint Detection and Response)** e **SIEM**, projetada para fornecer visibilidade profunda, proteção adaptativa e resposta automatizada (SOAR) contra adversários modernos. Com foco em **Furtividade Operacional** e **Forense Digital**, o Aegis transforma cada endpoint em uma sentinela inteligente.

### 🛡️ Engenharia de Defesa & Furtividade
- **Invisible Sentinel**: O agente Windows opera em modo infra-estrutural, sem janelas interativas (`CREATE_NO_WINDOW`), garantindo que a coleta de evidências e a monitoração ocorram de forma totalmente transparente e protegida.
- **Resiliência a File Locks**: Utiliza lógica avançada via `psutil` para gerenciar processos travados, permitindo remediação e desinstalação segura mesmo em sistemas sob estresse.
- **Integridade de Dados (Soft Delete)**: O Aegis prioriza a retenção forense. Dados de agentes não são purgados, mas sim marcados para preservação de histórico e trilhas de auditoria SIEM completas.

### 🚀 Capacidades SOC & SOAR
- **Hyper-Glass Forensic Interface**: Interface de alto desempenho com sincronização em tempo real (polling de 3s) para visualização de status, telemetria e screenshots instantâneos.
- **Análise Forense Dinâmica**: Monitoramento contínuo de árvores de processos, conexões de rede e integridade de serviços.
- **Orquestração de Resposta**:
    - **Host Isolation**: Isolamento imediato de ameaças via Firewall (Política Zero-Trust).
    - **System Recovery**: Reparo automatizado de integridade e imagem (`SFC`/`DISM`).
    - **Digital Wipe**: Desinstalação remota blindada para cenários de comprometimento total.
- **IA Copilot**: Assistente especializado com contexto total do endpoint para auxílio em triagens complexas.

### ⚙️ Implantação C2
- **Arquitetura**: Projetado para rodar em clusters Docker, garantindo alta disponibilidade e isolamento de processos.
- **Configuração**: Use o arquivo `.env` para definir os parâmetros de conexão do seu ambiente.

---

## English

Aegis is an advanced **Next-Gen EDR (Endpoint Detection and Response)** and **SIEM** platform, designed to provide deep visibility, adaptive protection, and automated response (SOAR) against modern adversaries. Focused on **Operational Stealth** and **Digital Forensics**, Aegis transforms every endpoint into an intelligent sentinel.

### 🛡️ Defense Engineering & Stealth
- **Invisible Sentinel**: The Windows agent operates in infrastructure mode, without interactive windows (`CREATE_NO_WINDOW`), ensuring that evidence collection and monitoring occur in a fully transparent and protected manner.
- **File Lock Resilience**: Uses advanced logic via `psutil` to manage locked processes, allowing safe remediation and uninstallation even on stressed systems.
- **Data Integrity (Soft Delete)**: Aegis prioritizes forensic retention. Agent data is not purged, but rather flagged for historical preservation and comprehensive SIEM audit trails.

### 🚀 SOC & SOAR Capabilities
- **Hyper-Glass Forensic Interface**: High-performance UI with real-time synchronization (3s polling) for status, telemetry, and instant screenshots.
- **Dynamic Forensic Analysis**: Continuous monitoring of process trees, network connections, and service integrity.
- **Response Orchestration**:
    - **Host Isolation**: Immediate threat isolation via Firewall (Zero-Trust Policy).
    - **System Recovery**: Automated integrity and image repair (`SFC`/`DISM`).
    - **Digital Wipe**: Shielded remote uninstallation for total compromise scenarios.
- **IA Copilot**: Specialized assistant with full endpoint context to assist in complex triage.

### ⚙️ C2 Deployment
- **Architecture**: Designed to run in Docker clusters, ensuring high availability and process isolation.
- **Configuration**: Use the `.env` file to define your environment's connection parameters.

---

### 🛠️ Quick Start / Início Rápido

**1. Setup Environment:**
```bash
git clone https://github.com/BernardoMancia/aegis-endpoint-defense.git
cp .env.example .env
```

**2. Deploy Infrastructure:**
```bash
docker-compose up -d --build
```

**3. Compile Agent:**
```bash
cd agent
# Recomenda-se compilação estática / Static build recommended
python setup.py build
```
