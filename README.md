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
O agente pode ser instalado de duas formas:
1. **Instalador MSI (Recomendado)**: Execute o arquivo `.msi` gerado na pasta `dist/` para uma instalação limpa no Windows.
2. **Manual**: Execute `python client_pc/agent_gui.py` (requer Python 3.x e permissões de Admin).

### 🌐 Deploy em Produção (Sem Domínio / IP:Porta)

#### Linux Server (Ubuntu/Debian)
1. Certifique-se de que as portas `5000` (API/Dashboard) estão abertas no firewall:
   ```bash
   sudo ufw allow 5000/tcp
   ```
2. No arquivo `.env`, configure o `SERVER_IP` com o IP público do seu servidor.
3. Suba o ambiente: `docker-compose up -d`.

#### Windows Server
1. Para rodar o servidor em produção no Windows sem Docker, recomenda-se o uso do `Waitress`:
   ```bash
   pip install waitress
   waitress-serve --port=5000 server_vps.app:app
   ```
2. Para manter o servidor rodando como um serviço, utilize o [NSSM](https://nssm.cc/):
   ```bash
   nssm install AegisServer
   ```
   (Selecione o caminho do python.exe e o script app.py).
3. Abra a porta `5000` no Windows Defender Firewall.

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
The agent can be installed in two ways:
1. **MSI Installer (Recommended)**: Run the `.msi` file from the `dist/` folder for a clean installation.
2. **Manual**: Run `python client_pc/agent_gui.py` (requires Python 3.x and Admin privileges).

### 🌐 Production Deployment (No Domain / IP:Port)

#### Linux Server (Ubuntu/Debian)
1. Ensure port `5000` (API/Dashboard) is open in the firewall:
   ```bash
   sudo ufw allow 5000/tcp
   ```
2. In the `.env` file, set `SERVER_IP` to your server's public IP.
3. Start the environment: `docker-compose up -d`.

#### Windows Server
1. To run the server in production on Windows without Docker, it's recommended to use `Waitress`:
   ```bash
   pip install waitress
   waitress-serve --port=5000 server_vps.app:app
   ```
2. To keep the server running as a service, use [NSSM](https://nssm.cc/):
   ```bash
   nssm install AegisServer
   ```
   (Select the python.exe path and the app.py script).
3. Open port `5000` in Windows Defender Firewall.
