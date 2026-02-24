# Aegis Endpoint Defense 🛡️

[Português](#português) | [English](#english)

---

## Português

Aegis é uma plataforma SIEM & EDR de código aberto projetada para monitoramento de segurança, detecção de ameaças e resposta automatizada (SOAR) em endpoints Windows.

### 🚀 Funcionalidades Principais
- **Dashboard SOC Integrado**: Gerenciamento centralizado de múltiplos agentes.
- **Ações SOAR Interativas**: 
    - Scan de Vulnerabilidades (UAC, Defender, Firewall).
    - Verificação de Integridade de Arquivos (FIM).
    - Scan de Portas e Conexões de Rede (Netstat).
    - Dump remoto de Event Logs do Windows.
- **Área Crítica de Segurança**: Isolamento de host via Firewall e Wipe remoto com 3 níveis de confirmação.
- **Chat SOC Admin-Agente**: Comunicação direta e persistente entre a equipe de segurança e o usuário final.
- **Aegis AI Assistant**: Chatbot inteligente com contexto total do agente para análise de ameaças.

### 🛠️ Instalação (Servidor C2)

#### Via Docker (Recomendado para Produção)
```bash
docker-compose up -d
```
O servidor estará disponível em `http://localhost:5000`.

#### Manual (Desenvolvimento)
1. Instale as dependências: `pip install -r server_vps/requirements.txt`
2. Configure o `.env` seguindo o `.env.example`.
3. Rode o servidor: `python server_vps/app.py`

### 💻 Agente Windows
O agente está localizado em `client_pc/agent_gui.py`. Ele requer Python 3.x e permissões administrativas para realizar as correções de segurança.

---

## English

Aegis is an open-source SIEM & EDR platform designed for security monitoring, threat detection, and automated response (SOAR) on Windows endpoints.

### 🚀 Key Features
- **Integrated SOC Dashboard**: Centralized management of multiple agents.
- **Interactive SOAR Actions**: 
    - Vulnerability Scanning (UAC, Defender, Firewall).
    - File Integrity Monitoring (FIM).
    - Network Port and Connection Scanning (Netstat).
    - Remote Windows Event Log dumping.
- **Critical Security Area**: Host isolation via Firewall and remote Wipe with 3 confirmation levels.
- **SOC Admin-Agent Chat**: Direct and persistent communication between the security team and the end-user.
- **Aegis AI Assistant**: Intelligent chatbot with full agent context for threat analysis.

### 🛠️ Installation (C2 Server)

#### Via Docker (Recommended for Production)
```bash
docker-compose up -d
```
The server will be available at `http://localhost:5000`.

#### Manual (Development)
1. Install dependencies: `pip install -r server_vps/requirements.txt`
2. Configure `.env` following `.env.example`.
3. Run the server: `python server_vps/app.py`

### 💻 Windows Agent
The agent is located at `client_pc/agent_gui.py`. It requires Python 3.x and administrative privileges to perform security remediations.
