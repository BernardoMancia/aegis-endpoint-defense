import os
import re

TEMPLATES_DIR = "server/templates"

GLOBAL_CSS = """
/* Aegis Hyper-Glass Design System */
@import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

:root {
    --deep-bg: #030712;
    --glass-bg: rgba(17, 24, 39, 0.45);
    --glass-border: rgba(255, 255, 255, 0.08);
    --neon-blue: #0ea5e9;
    --neon-blue-glow: rgba(14, 165, 233, 0.4);
    --neon-purple: #8b5cf6;
    --neon-purple-glow: rgba(139, 92, 246, 0.4);
    --neon-emerald: #10b981;
    --neon-rose: #f43f5e;
    --text-primary: #f8fafc;
    --text-muted: #94a3b8;
}

* { box-sizing: border-box; font-family: 'Outfit', sans-serif; }

body {
    background-color: var(--deep-bg);
    color: var(--text-primary);
    margin: 0;
    min-height: 100vh;
    overflow-x: hidden;
    position: relative;
}

/* Background AnimatedMesh */
.bg-mesh {
    position: fixed; inset: 0; z-index: -1;
    background: radial-gradient(circle at 10% 20%, rgba(14, 165, 233, 0.05) 0%, transparent 40%),
                radial-gradient(circle at 90% 80%, rgba(139, 92, 246, 0.05) 0%, transparent 40%);
    filter: blur(80px);
    animation: meshFlow 20s ease-in-out infinite alternate;
}
@keyframes meshFlow {
    0% { transform: scale(1) translate(0, 0); }
    100% { transform: scale(1.1) translate(20px, 10px); }
}

/* Glassmorphism Generic Card */
.hyper-glass {
    background: var(--glass-bg);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1px solid var(--glass-border);
    border-radius: 18px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
}

/* Modern Scrollbars */
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: rgba(255, 255, 255, 0.1); border-radius: 10px; }
::-webkit-scrollbar-thumb:hover { background: var(--neon-blue); }

/* Inputs Fix */
.aegis-input {
    background: rgba(0, 0, 0, 0.3) !important;
    border: 1px solid var(--glass-border) !important;
    color: var(--text-primary) !important;
    border-radius: 10px;
    padding: 12px 16px;
    outline: none;
    transition: all 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    width: 100%;
    color-scheme: dark;
}
.aegis-input:focus {
    border-color: var(--neon-blue) !important;
    box-shadow: 0 0 15px var(--neon-blue-glow) !important;
    transform: translateY(-1px);
}

/* Premium Buttons */
.aegis-btn-primary {
    background: linear-gradient(135deg, var(--neon-blue), #0284c7);
    color: white;
    font-weight: 600;
    padding: 12px 24px;
    border-radius: 12px;
    border: none;
    cursor: pointer;
    transition: all 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    box-shadow: 0 4px 15px var(--neon-blue-glow);
    display: inline-flex; align-items: center; gap: 8px;
}
.aegis-btn-primary:hover {
    transform: translateY(-2px) scale(1.02);
    box-shadow: 0 8px 25px var(--neon-blue-glow);
}
.aegis-btn-primary:active { transform: translateY(1px); }

.aegis-btn-secondary {
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid var(--glass-border);
    color: var(--text-primary);
    padding: 10px 20px;
    border-radius: 12px;
    transition: all 0.3s ease;
}
.aegis-btn-secondary:hover { background: rgba(255, 255, 255, 0.1); border-color: var(--neon-blue); }

/* Toasts */
#toast-container { position: fixed; top: 24px; right: 24px; z-index: 9999; display: flex; flex-direction: column; gap: 10px; }
.toast {
    background: rgba(15, 23, 42, 0.9);
    backdrop-filter: blur(10px);
    border: 1px solid var(--glass-border);
    padding: 14px 20px;
    border-radius: 12px;
    color: white;
    font-size: 14px;
    display: flex; align-items: center; gap: 12px;
    transform: translateX(120%);
    transition: transform 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55);
}
.toast.show { transform: translateX(0); }

/* Modal System */
.modal-overlay {
    position: fixed; inset: 0; background: rgba(0,0,0,0.7);
    backdrop-filter: blur(10px); z-index: 2000;
    display: flex; items-center: center; justify-content: center;
    opacity: 0; pointer-events: none; transition: all 0.3s ease;
}
.modal-overlay.active { opacity: 1; pointer-events: auto; }
.modal-content {
    width: 100%; max-width: 600px; max-height: 80vh;
    transform: translateY(20px); transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
}
.modal-overlay.active .modal-content { transform: translateY(0); }

@keyframes headShake {
  0% { transform: translateX(0); }
  6.5% { transform: translateX(-6px) rotateY(-9deg); }
  18.5% { transform: translateX(5px) rotateY(7deg); }
  31.5% { transform: translateX(-3px) rotateY(-5deg); }
  43.5% { transform: translateX(2px) rotateY(3deg); }
  50% { transform: translateX(0); }
}
.animate-headShake { animation: headShake 0.6s ease-in-out; }
"""

def write_file(name, txt):
    p = os.path.join(TEMPLATES_DIR, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(txt)

def get_sidebar(active_item):
    return f"""
    <aside class="w-20 flex flex-col items-center py-8 gap-6 z-50">
        <a href="/" class="w-12 h-12 rounded-2xl bg-gradient-to-br from-sky-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-sky-500/20 mb-4 cursor-pointer hover:scale-110 transition-transform">
            <i data-lucide="shield" class="text-white w-6 h-6"></i>
        </a>
        
        <nav class="flex-1 flex flex-col gap-4">
            <a href="/" class="p-3 {'hyper-glass text-sky-400' if active_item == 'dashboard' else 'text-slate-500'} cursor-pointer hover:text-white transition-colors" title="Dashboard">
                <i data-lucide="layout-dashboard" class="w-6 h-6"></i>
            </a>
            <a href="/history" class="p-3 {'hyper-glass text-sky-400' if active_item == 'history' else 'text-slate-500'} cursor-pointer hover:text-white transition-colors" title="Histórico de Incidentes">
                <i data-lucide="clock" class="w-6 h-6"></i>
            </a>
            <div class="p-3 text-slate-500 cursor-pointer hover:text-white transition-colors" title="Threat Intel (Em breve)">
                <i data-lucide="crosshairs" class="w-6 h-6"></i>
            </div>
        </nav>
        
        <div class="flex flex-col gap-4">
            <a href="/admin/users" class="p-3 {'hyper-glass text-sky-400' if active_item == 'admin' else 'text-slate-500'} cursor-pointer hover:text-white transition-colors" title="Gestão de Usuários">
                <i data-lucide="settings" class="w-6 h-6"></i>
            </a>
            <a href="/profile" class="w-10 h-10 rounded-full border-2 {'border-sky-500 shadow-[0_0_10px_var(--neon-blue-glow)]' if active_item == 'profile' else 'border-slate-700'} overflow-hidden hover:border-sky-500 transition-colors" title="Meu Perfil">
                {{% if user and user.avatar_url %}}
                <img src="{{{{ user.avatar_url }}}}" alt="Avatar" class="w-full h-full object-cover">
                {{% else %}}
                <img src="https://api.dicebear.com/7.x/initials/svg?seed={{{{ session.get('soc_user', 'Aegis') }}}}" alt="Avatar">
                {{% endif %}}
            </a>
            <a href="/logout" class="p-3 text-rose-500 cursor-pointer hover:text-rose-400 transition-all" title="Sair">
                <i data-lucide="log-out" class="w-6 h-6"></i>
            </a>
        </div>
    </aside>
    """

def apply_layout(content, title, active_item=None):
    head = f"""
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest"></script>
    <style>{GLOBAL_CSS}</style>
    """
    
    if active_item:
        sidebar = get_sidebar(active_item)
        body_content = f"""
        <div class="flex h-screen overflow-hidden">
            {sidebar}
            <main class="flex-1 p-8 overflow-y-auto">
                {content}
            </main>
        </div>
        """
    else:
        body_content = content

    return f"""<!DOCTYPE html>
<html>
<head>
    {head}
</head>
<body>
    <div class="bg-mesh"></div>
    {body_content}
    <div id="toast-container"></div>
    <script>lucide.createIcons();</script>
</body>
</html>"""

def rebuild_dashboard():
    dashboard_html = """
            <header class="flex justify-between items-center mb-10">
                <div>
                    <h1 class="text-3xl font-bold tracking-tight">Status do Ambiente</h1>
                    <p class="text-slate-400">Visão geral em tempo real dos seus endpoints gerenciados.</p>
                </div>
                <div class="flex gap-4">
                    <div class="hyper-glass px-4 py-2 flex items-center gap-2 border-emerald-500/20">
                        <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                        <span class="text-sm font-medium">C2 Operacional</span>
                    </div>
                </div>
            </header>

            <!-- Bento Stats -->
            <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-10">
                <div onclick="showStatDetails('total')" class="hyper-glass p-6 cursor-pointer hover:border-sky-500/30 transition-all group">
                    <div class="flex justify-between items-start mb-4">
                        <div class="p-2 bg-sky-500/10 rounded-lg text-sky-500 group-hover:scale-110 transition-transform"><i data-lucide="monitor" class="w-5 h-5"></i></div>
                        <span class="text-xs text-emerald-400 font-bold">+12%</span>
                    </div>
                    <h3 class="text-slate-500 text-sm font-medium">Endpoints Totais</h3>
                    <p class="text-3xl font-bold mt-1" id="stat-total-agents">--</p>
                </div>
                <div onclick="showStatDetails('online')" class="hyper-glass p-6 cursor-pointer hover:border-emerald-500/30 transition-all group">
                    <div class="flex justify-between items-start mb-4">
                        <div class="p-2 bg-emerald-500/10 rounded-lg text-emerald-500 group-hover:scale-110 transition-transform"><i data-lucide="wifi" class="w-5 h-5"></i></div>
                        <span class="text-xs text-emerald-400 font-bold">Online</span>
                    </div>
                    <h3 class="text-slate-500 text-sm font-medium">Agentes Online</h3>
                    <p class="text-3xl font-bold mt-1 text-emerald-400" id="stat-online-agents">--</p>
                </div>
                <div onclick="showStatDetails('incidents')" class="hyper-glass p-6 cursor-pointer hover:border-rose-500/30 transition-all group">
                    <div class="flex justify-between items-start mb-4">
                        <div class="p-2 bg-rose-500/10 rounded-lg text-rose-400 group-hover:scale-110 transition-transform"><i data-lucide="shield-alert" class="w-5 h-5"></i></div>
                        <span class="text-xs text-rose-400 font-bold">Crítico</span>
                    </div>
                    <h3 class="text-slate-500 text-sm font-medium">Ameaças Ativas</h3>
                    <p class="text-3xl font-bold mt-1 text-rose-500" id="stat-incidents">--</p>
                </div>
                <div onclick="showStatDetails('health')" class="hyper-glass p-6 cursor-pointer hover:border-indigo-500/30 transition-all group">
                    <div class="flex justify-between items-start mb-4">
                        <div class="p-2 bg-indigo-500/10 rounded-lg text-indigo-400 group-hover:scale-110 transition-transform"><i data-lucide="activity" class="w-5 h-5"></i></div>
                        <span class="text-xs text-indigo-400">Normal</span>
                    </div>
                    <h3 class="text-slate-500 text-sm font-medium">Health Score</h3>
                    <p class="text-3xl font-bold mt-1">98%</p>
                </div>
            </div>

            <!-- Stat Detail Modal -->
            <div id="stat-detail-modal" class="modal-overlay flex items-center justify-center p-6" onclick="if(event.target === this) closeStatModal()">
                <div class="modal-content hyper-glass p-8 flex flex-col shadow-2xl border-white/10 max-h-[80vh]">
                    <div class="flex justify-between items-center mb-6">
                        <div class="flex items-center gap-3">
                            <div id="modal-icon-bg" class="p-3 rounded-xl">
                                <i id="modal-icon" data-lucide="activity" class="w-6 h-6"></i>
                            </div>
                            <div>
                                <h2 id="modal-title" class="text-xl font-bold">Título da Estatística</h2>
                                <p id="modal-subtitle" class="text-[10px] text-slate-500 font-mono uppercase tracking-widest">DETALHAMENTO TÉCNICO</p>
                            </div>
                        </div>
                        <button onclick="closeStatModal()" class="p-2 hover:bg-white/10 rounded-lg text-slate-400 hover:text-white transition-colors">
                            <i data-lucide="x" class="w-6 h-6"></i>
                        </button>
                    </div>
                    <div id="modal-body" class="flex-1 overflow-y-auto pr-2 custom-scrollbar">
                        <!-- Content here -->
                    </div>
                </div>
            </div>

            <!-- Content Grid -->
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <!-- Endpoint Grid -->
                <div class="lg:col-span-2">
                    <div class="flex items-center justify-between mb-6">
                        <h2 class="text-xl font-bold">Endpoints Gerenciados</h2>
                        <div class="flex gap-2">
                            <input type="text" placeholder="Filtrar host..." class="aegis-input w-48 !py-2 !text-xs">
                            <button class="aegis-btn-secondary !text-xs !py-2">Filtros</button>
                        </div>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4" id="agents-grid">
                        <!-- Agents populated here -->
                    </div>
                </div>

                <!-- Live Logs / Incidents -->
                <div class="space-y-6">
                    <h2 class="text-xl font-bold">Atividade Recente</h2>
                    <div class="hyper-glass p-6 h-[500px] flex flex-col">
                        <div id="incidents-feed" class="flex-1 overflow-y-auto space-y-4 pr-2">
                            <!-- Logs here -->
                        </div>
                    </div>
                </div>
            </div>

            <!-- Slide Panel -->
            <div id="agent-panel" class="fixed top-0 right-0 w-[600px] h-screen bg-slate-900/98 backdrop-blur-3xl border-l border-white/5 z-[100] translate-x-full transition-all duration-500 ease-in-out shadow-2xl flex flex-col">
                <div class="p-6 border-b border-white/5 flex justify-between items-center bg-white/[0.02]">
                    <div>
                        <div class="flex items-center gap-2">
                            <h2 class="text-2xl font-black tracking-tighter" id="panel-hostname">Hostname</h2>
                            <span id="panel-status-pill" class="px-2 py-0.5 rounded text-[9px] font-bold uppercase transition-all"></span>
                        </div>
                        <p class="text-slate-500 text-[10px] font-mono mt-1" id="panel-agent-id">ID: --</p>
                    </div>
                    <div class="flex gap-2">
                        <button onclick="fetchAgentDetail()" class="p-2 hover:bg-white/10 rounded-lg text-slate-400" title="Atualizar Dados"><i data-lucide="refresh-cw" class="w-5 h-5"></i></button>
                        <button onclick="closeAgentPanel()" class="p-2 hover:bg-rose-500/20 rounded-lg text-slate-400 hover:text-rose-500 transition-colors">
                            <i data-lucide="x" class="w-6 h-6"></i>
                        </button>
                    </div>
                </div>

                <div class="flex-1 overflow-y-auto p-6 space-y-8 custom-scrollbar">
                    <!-- Host Info Grid -->
                    <div class="grid grid-cols-2 gap-4">
                        <div class="p-4 rounded-2xl bg-white/5 border border-white/5 group hover:border-sky-500/30 transition-all">
                            <p class="text-[9px] uppercase text-slate-500 font-black mb-1 flex items-center gap-1"><i data-lucide="folder" class="w-3 h-3"></i> Path</p>
                            <p class="text-[11px] truncate font-mono text-slate-300" id="panel-path">--</p>
                        </div>
                        <div class="p-4 rounded-2xl bg-white/5 border border-white/5 group hover:border-sky-500/30 transition-all">
                            <p class="text-[9px] uppercase text-slate-500 font-black mb-1 flex items-center gap-1"><i data-lucide="cpu" class="w-3 h-3"></i> Platform</p>
                            <p class="text-[11px] font-mono text-slate-300" id="panel-platform">--</p>
                        </div>
                        <div class="p-4 rounded-2xl bg-white/5 border border-white/5 group hover:border-sky-500/30 transition-all">
                            <p class="text-[9px] uppercase text-slate-500 font-black mb-1 flex items-center gap-1"><i data-lucide="globe" class="w-3 h-3"></i> IP Address</p>
                            <p class="text-[11px] font-mono text-slate-300" id="panel-ip">--</p>
                        </div>
                        <div class="p-4 rounded-2xl bg-white/5 border border-white/5 group hover:border-sky-500/30 transition-all">
                            <p class="text-[9px] uppercase text-slate-500 font-black mb-1 flex items-center gap-1"><i data-lucide="hash" class="w-3 h-3"></i> MAC</p>
                            <p class="text-[11px] font-mono text-slate-300" id="panel-mac">--</p>
                        </div>
                    </div>

                    <!-- Screenshot Preview -->
                    <div id="screenshot-container" class="hidden space-y-3">
                        <h3 class="text-xs font-black uppercase text-slate-500 flex items-center gap-2"><i data-lucide="image" class="w-4 h-4"></i> Última Screenshot</h3>
                        <div class="relative rounded-2xl overflow-hidden border border-white/10 group cursor-zoom-in" onclick="this.classList.toggle('fixed'); this.classList.toggle('inset-0'); this.classList.toggle('z-[200]'); this.classList.toggle('bg-black/90'); this.classList.toggle('p-10');">
                            <img id="panel-screenshot" src="" class="w-full h-auto object-cover max-h-48 group-hover:scale-105 transition-transform" />
                            <div class="absolute inset-0 bg-gradient-to-t from-black/60 to-transparent"></div>
                        </div>
                    </div>

                    <!-- Terminal -->
                    <div class="space-y-3">
                        <div class="flex justify-between items-end">
                            <h3 class="text-sm font-black flex items-center gap-2"><i data-lucide="terminal" class="w-4 h-4 text-sky-400"></i> Terminal C2</h3>
                            <button onclick="document.getElementById('terminal-output').innerHTML=''" class="text-[10px] text-slate-600 hover:text-slate-400 uppercase font-black">Limpar</button>
                        </div>
                        <div class="rounded-2xl bg-black/80 border border-white/5 p-5 font-mono text-[11px] h-72 overflow-y-auto mb-3 shadow-inner custom-scrollbar" id="terminal-output">
                            <span class="text-slate-600">Aguardando seleção de agente...</span>
                        </div>
                        
                        <!-- Quick Commands -->
                        <div class="flex flex-wrap gap-2 mb-2">
                             <button onclick="quickCommand('PROCESSLIST')" class="px-2 py-1 rounded bg-white/5 border border-white/5 text-[9px] font-bold text-slate-400 hover:bg-sky-500/20 hover:text-sky-400 transition-all uppercase tracking-tighter">Processes</button>
                             <button onclick="quickCommand('NETSTAT')" class="px-2 py-1 rounded bg-white/5 border border-white/5 text-[9px] font-bold text-slate-400 hover:bg-sky-500/20 hover:text-sky-400 transition-all uppercase tracking-tighter">Network</button>
                             <button onclick="quickCommand('SYSINFO')" class="px-2 py-1 rounded bg-white/5 border border-white/5 text-[9px] font-bold text-slate-400 hover:bg-sky-500/20 hover:text-sky-400 transition-all uppercase tracking-tighter">Sysinfo</button>
                             <button onclick="quickCommand('USERS')" class="px-2 py-1 rounded bg-white/5 border border-white/5 text-[9px] font-bold text-slate-400 hover:bg-sky-500/20 hover:text-sky-400 transition-all uppercase tracking-tighter">Users</button>
                        </div>

                        <div class="flex gap-2">
                            <input type="text" id="terminal-input" class="aegis-input flex-1 !py-3 !text-xs font-mono !bg-black/40" placeholder="Execute um comando shell..." onkeydown="if(event.key==='Enter')sendTerminalCommand()">
                            <button onclick="sendTerminalCommand()" class="aegis-btn-primary !py-3 !px-5"><i data-lucide="send" class="w-4 h-4"></i></button>
                        </div>
                    </div>

                    <!-- Critical Data / Security Context -->
                    <div id="critical-data-section" class="space-y-4">
                        <h3 class="text-sm font-black flex items-center gap-2"><i data-lucide="shield-alert" class="w-4 h-4 text-rose-500"></i> Segurança e Contexto Crítico</h3>
                        <div id="panel-incidents-list" class="space-y-2">
                            <!-- Agent specific incidents -->
                        </div>
                        <div id="panel-events-list" class="space-y-2">
                            <!-- Agent specific events -->
                        </div>
                    </div>

                    <!-- SOAR Actions -->
                    <div class="space-y-4 pb-10">
                        <h3 class="text-sm font-black flex items-center gap-2"><i data-lucide="play" class="w-4 h-4 text-emerald-500"></i> Ações de Orquestração</h3>
                        <div class="grid grid-cols-2 gap-3">
                            <button onclick="soarAction('screenshot')" class="aegis-btn-secondary !text-[11px] !py-3 flex items-center justify-center gap-2 hover:border-sky-500/50"><i data-lucide="camera" class="w-4 h-4 text-sky-400"></i> Screenshot</button>
                            <button onclick="soarAction('force_scan_vulns')" class="aegis-btn-secondary !text-[11px] !py-3 flex items-center justify-center gap-2 hover:border-emerald-500/50"><i data-lucide="activity" class="w-4 h-4 text-emerald-400"></i> Vulnerabilidades</button>
                            <button onclick="soarAction('force_scan_fim')" class="aegis-btn-secondary !text-[11px] !py-3 flex items-center justify-center gap-2 hover:border-purple-500/50"><i data-lucide="file-check" class="w-4 h-4 text-purple-400"></i> FIM Scan</button>
                            <button onclick="soarAction('force_logs')" class="aegis-btn-secondary !text-[11px] !py-3 flex items-center justify-center gap-2 hover:border-amber-500/50"><i data-lucide="database" class="w-4 h-4 text-amber-400"></i> Coletar Logs</button>
                        </div>
                        
                        <div class="pt-6 border-t border-white/5">
                            <h4 class="text-[10px] font-black text-rose-500 uppercase mb-4 tracking-[0.2em] flex items-center gap-2 opacity-50"><i data-lucide="alert-octagon" class="w-3 h-3"></i> Protocolos de contenção de alto risco</h4>
                            <div class="grid grid-cols-2 gap-3" id="risk-zone-actions">
                                <!-- Dynamic risk buttons -->
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Floating Chat -->
            <div id="ai-chat-bubble" onclick="toggleAIChat()" class="fixed bottom-6 right-6 w-14 h-14 rounded-full bg-gradient-to-br from-purple-600 to-indigo-700 flex items-center justify-center shadow-2xl cursor-pointer hover:scale-110 transition-all z-[1000] border-2 border-white/20">
                <i data-lucide="message-square" class="text-white w-6 h-6"></i>
            </div>
            <div id="ai-chat-window" class="fixed bottom-24 right-6 w-96 h-[500px] hyper-glass z-[1000] translate-y-10 opacity-0 pointer-events-none transition-all duration-300 flex flex-col overflow-hidden">
                <div class="p-4 border-b border-white/10 bg-gradient-to-r from-purple-500/10 to-transparent flex justify-between items-center">
                    <div class="flex items-center gap-2">
                        <i data-lucide="sparkles" class="text-purple-400 w-4 h-4"></i>
                        <h4 class="text-sm font-bold">Aegis AI Copilot</h4>
                    </div>
                    <button onclick="toggleAIChat()" class="text-slate-500 hover:text-white transition-colors"><i data-lucide="minus" class="w-4 h-4"></i></button>
                </div>
                <div class="flex-1 overflow-y-auto p-4 space-y-4" id="ai-chat-messages">
                    <div class="text-xs text-slate-500 italic text-center">Inicie uma conversa para análise forense ou comandos.</div>
                </div>
                <div class="p-4 bg-black/20 border-t border-white/10 flex gap-2">
                    <input type="text" id="ai-chat-input" class="aegis-input !py-2 !text-xs" placeholder="Pergunte ao Aegis AI..." onkeydown="if(event.key==='Enter')sendAIChat()">
                    <button onclick="sendAIChat()" class="p-2 bg-purple-600 rounded-lg text-white"><i data-lucide="send" class="w-4 h-4"></i></button>
                </div>
            </div>

            <script>
                let currentAgents = [];
                let selectedAgentId = null;
                let lastResultTimestamp = null;
                let detailTimer = null;

                function closeAgentPanel() {
                    document.getElementById('agent-panel').classList.add('translate-x-full');
                    selectedAgentId = null;
                    if(detailTimer) clearInterval(detailTimer);
                }

                async function openAgentPanel(agentId) {
                    selectedAgentId = agentId;
                    const agent = currentAgents.find(a => a.id === agentId);
                    if(!agent) return;
                    
                    document.getElementById('agent-panel').classList.remove('translate-x-full');
                    document.getElementById('terminal-output').innerHTML = '<span class="text-sky-400/50 font-mono">DEBUG: Handshake com agente iniciado...</span>';
                    
                    lastResultTimestamp = null;
                    await fetchAgentDetail();
                    
                    if(detailTimer) clearInterval(detailTimer);
                    detailTimer = setInterval(fetchAgentDetail, 3000);
                }

                async function fetchAgentDetail() {
                    if(!selectedAgentId) return;
                    try {
                        const res = await fetch(`/api/agent/${selectedAgentId}/detail`);
                        if(res.ok) {
                            const data = await res.json();
                            const ag = data.agent;
                            
                            // Basic Info
                            document.getElementById('panel-hostname').innerText = ag.hostname;
                            document.getElementById('panel-agent-id').innerText = `ID: ${ag.id}`;
                            document.getElementById('panel-platform').innerText = ag.platform;
                            document.getElementById('panel-path').innerText = data.extra_data?.execution_path || '---';
                            document.getElementById('panel-ip').innerText = ag.ip_address || '---';
                            document.getElementById('panel-mac').innerText = ag.mac_address || '---';

                            // Status Pill
                            const pill = document.getElementById('panel-status-pill');
                            if(pill) {
                                pill.innerText = ag.status;
                                pill.className = `px-2 py-0.5 rounded text-[9px] font-bold uppercase ${
                                    ag.status === 'online' ? 'bg-emerald-500/20 text-emerald-500' : 
                                    ag.status === 'isolated' ? 'bg-rose-500/20 text-rose-500' : 'bg-slate-500/20 text-slate-500'
                                }`;
                            }

                            // Screenshot
                            const screenshotContainer = document.getElementById('screenshot-container');
                            if(ag.last_screenshot) {
                                screenshotContainer.classList.remove('hidden');
                                const snapRes = await fetch(`/api/screenshot/${selectedAgentId}`);
                                if(snapRes.ok) {
                                    const snapData = await snapRes.json();
                                    document.getElementById('panel-screenshot').src = `data:image/png;base64,${snapData.screenshot_b64}`;
                                }
                            } else {
                                screenshotContainer.classList.add('hidden');
                            }

                            // Output Terminal
                            if(data.last_command_result) {
                                const newTime = data.agent.command_result_time;
                                if(newTime !== lastResultTimestamp) {
                                    lastResultTimestamp = newTime;
                                    const out = document.getElementById('terminal-output');
                                    const result = data.last_command_result;
                                    out.innerHTML += `<div class="mt-4 border-t border-white/5 pt-2">
                                        <div class="text-emerald-500 font-bold mb-1">STDOUT (${new Date(newTime).toLocaleTimeString()}):</div>
                                        <pre class="bg-white/5 p-2 rounded text-slate-300 overflow-x-auto">${result.output || 'No output'}</pre>
                                        <div class="text-[10px] text-slate-500 mt-1">Exit Code: ${result.exit_code}</div>
                                    </div>`;
                                    out.scrollTop = out.scrollHeight;
                                }
                            }

                                // Defensive Zone Buttons
                            const riskZone = document.getElementById('risk-zone-actions');
                            if(riskZone) {
                                let riskHtml = `<button onclick="confirmUninstall(${ag.id})" class="p-4 rounded-2xl border border-white/10 bg-white/5 text-slate-300 text-[11px] font-black hover:bg-rose-500/10 hover:text-rose-400 hover:border-rose-500/30 transition-all flex flex-col items-center gap-2 group">
                                    <i data-lucide="trash-2" class="w-6 h-6 group-hover:scale-110 transition-transform"></i> DESINSTALAR AGENTE
                                </button>`;
                                
                                if(ag.isolation_active) {
                                    riskHtml += `<button onclick="soarAction('unisolate')" class="p-4 rounded-2xl border border-emerald-500/20 bg-emerald-500/5 text-emerald-500 text-[11px] font-black hover:bg-emerald-500/20 transition-all flex flex-col items-center gap-2 group">
                                        <i data-lucide="shield-off" class="w-6 h-6 group-hover:scale-110 transition-transform"></i> REMOVER ISOLAMENTO
                                    </button>`;
                                } else {
                                    riskHtml += `<button onclick="soarAction('isolate')" class="p-4 rounded-2xl border border-rose-500/20 bg-rose-500/5 text-rose-500 text-[11px] font-black hover:bg-rose-500/20 transition-all flex flex-col items-center gap-2 group">
                                        <i data-lucide="lock" class="w-6 h-6 group-hover:scale-110 transition-transform"></i> ATIVAR ISOLAMENTO
                                    </button>`;
                                }
                                riskZone.innerHTML = riskHtml;
                            }

                            // Render specific Incidents/Events
                            const incList = document.getElementById('panel-incidents-list');
                            if(data.open_incidents && data.open_incidents.length > 0) {
                                incList.innerHTML = data.open_incidents.map(i => `
                                    <div class="px-3 py-2 rounded-xl bg-rose-500/5 border border-rose-500/10 flex items-center gap-3">
                                        <i data-lucide="alert-circle" class="w-3 h-3 text-rose-500"></i>
                                        <div class="flex-1">
                                            <div class="text-[10px] font-bold text-rose-200">${i.title}</div>
                                            <div class="text-[8px] text-rose-500/70 font-mono">${new Date(i.created_at).toLocaleTimeString()}</div>
                                        </div>
                                    </div>
                                `).join('');
                            } else {
                                incList.innerHTML = '<div class="text-[10px] text-slate-600 italic px-2">Nenhum incidente ativo.</div>';
                            }

                            const evList = document.getElementById('panel-events-list');
                            if(data.recent_events && data.recent_events.length > 0) {
                                evList.innerHTML = data.recent_events.map(e => `
                                    <div class="px-3 py-2 rounded-xl bg-white/5 border border-white/5 flex items-center gap-3">
                                        <i data-lucide="activity" class="w-3 h-3 text-sky-400"></i>
                                        <div class="flex-1">
                                            <div class="text-[10px] text-slate-300 font-mono">${e.event_type}</div>
                                            <div class="text-[8px] text-slate-500">${new Date(e.timestamp).toLocaleTimeString()}</div>
                                        </div>
                                    </div>
                                `).join('');
                                if(data.recent_events.length > 5) evList.innerHTML += '<div class="text-[8px] text-center text-slate-600 pt-1">Ver todos no histórico...</div>';
                            } else {
                                evList.innerHTML = '<div class="text-[10px] text-slate-600 italic px-2">Aguardando telemetria...</div>';
                            }

                            lucide.createIcons();
                        }
                    } catch(e) { console.error("Error fetching agent detail:", e); }
                }

                function toggleAIChat() {
                    const win = document.getElementById('ai-chat-window');
                    win.classList.toggle('opacity-0'); win.classList.toggle('pointer-events-none'); win.classList.toggle('translate-y-10');
                }

                async function fetchData() {
                    try {
                        const statsRes = await fetch('/api/stats');
                        if(statsRes.ok) {
                            const s = await statsRes.json();
                            document.getElementById('stat-total-agents').innerText = s.agents?.total ?? 0;
                            document.getElementById('stat-online-agents').innerText = s.agents?.online ?? 0;
                            document.getElementById('stat-incidents').innerText = s.incidents?.open ?? 0;
                        }
                        const agentsRes = await fetch('/api/agents');
                        if(agentsRes.ok) { currentAgents = await agentsRes.json(); renderAgents(); }
                        const incRes = await fetch('/api/incidents');
                        if(incRes.ok) { const id = await incRes.json(); renderIncidents(id.incidents || []); }
                    } catch(e) { console.error(e); }
                }

                function renderAgents() {
                    const grid = document.getElementById('agents-grid');
                    grid.innerHTML = currentAgents.map(ag => `
                        <div onclick="openAgentPanel(${ag.id})" ondblclick="window.location.href='/agent/${ag.id}'" class="hyper-glass p-5 cursor-pointer border-l-4 ${ag.status === 'online' ? 'border-l-emerald-500' : ag.status === 'isolated' ? 'border-l-rose-500' : 'border-l-slate-700'} group hover:scale-[1.02] transition-all relative overflow-hidden">
                            <div class="flex justify-between items-start mb-2">
                                <div class="flex items-center gap-2">
                                    <span class="w-2 h-2 rounded-full ${ag.status === 'online' ? 'bg-emerald-500' : ag.status === 'isolated' ? 'bg-rose-500' : 'bg-slate-500'}"></span>
                                    <span class="font-bold text-sm tracking-tight">${ag.hostname}</span>
                                </div>
                                <i data-lucide="${ag.platform.includes('win') ? 'monitor' : 'smartphone'}" class="w-4 h-4 text-slate-500"></i>
                            </div>
                            <p class="text-[10px] text-slate-500 font-mono">${ag.ip_address || '0.0.0.0'}</p>
                            ${ag.status === 'isolated' ? '<div class="absolute inset-0 bg-rose-500/5 pointer-events-none"></div>' : ''}
                        </div>
                    `).join('');
                    lucide.createIcons();
                }

                function renderIncidents(incidents) {
                    const feed = document.getElementById('incidents-feed');
                    feed.innerHTML = incidents.map(inc => `
                        <div class="p-4 rounded-2xl bg-white/[0.03] border border-white/5 flex gap-4 transition-all hover:bg-white/[0.08]">
                            <div class="mt-1 ${inc.severity === 'CRITICAL' ? 'text-rose-500' : 'text-amber-500'}">
                                <i data-lucide="${inc.severity === 'CRITICAL' ? 'shield-alert' : 'alert-triangle'}" class="w-5 h-5"></i>
                            </div>
                            <div>
                                <h4 class="text-sm font-black tracking-tight">${inc.title}</h4>
                                <p class="text-[11px] text-slate-500 mt-1 line-clamp-2 leading-relaxed">${inc.description}</p>
                                <div class="flex gap-2 mt-3 items-center">
                                    <span class="text-[9px] font-black px-2 py-0.5 rounded bg-white/5 border border-white/5 uppercase">${inc.severity}</span>
                                    <span class="text-[9px] text-slate-600 font-mono">${new Date(inc.created_at).toLocaleTimeString()}</span>
                                </div>
                            </div>
                        </div>
                    `).join('');
                    lucide.createIcons();
                }

                function showToast(msg, type='info') {
                    const container = document.getElementById('toast-container');
                    const toast = document.createElement('div');
                    toast.className = 'toast shadow-2xl border-l-4';
                    let icon = 'info';
                    if(type === 'error') { toast.classList.add('border-rose-500'); icon = 'alert-octagon'; }
                    else if(type === 'success') { toast.classList.add('border-emerald-500'); icon = 'check-circle'; }
                    else { toast.classList.add('border-sky-500'); icon = 'info'; }
                    
                    toast.innerHTML = `<i data-lucide="${icon}" class="w-5 h-5"></i><span>${msg}</span>`;
                    container.appendChild(toast);
                    lucide.createIcons();
                    setTimeout(() => toast.classList.add('show'), 10);
                    setTimeout(() => { toast.classList.remove('show'); setTimeout(() => toast.remove(), 500); }, 5000);
                }

                async function soarAction(action) {
                    if(!selectedAgentId) return;
                    showToast(`Disparando comando: ${action.toUpperCase()}...`);
                    const endpoint = action === 'isolate' ? '/control/isolate' : 
                                   action === 'unisolate' ? '/control/unisolate' : 
                                   `/api/soar/${selectedAgentId}`;
                    
                    try {
                        const res = await fetch(endpoint, {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({agent_id: selectedAgentId, action})
                        });
                        const data = await res.json();
                        if(data.status === 'ok') showToast("Ação confirmada e enfileirada!", "success");
                        else showToast(data.error || "Operação falhou.", "error");
                    } catch(e) { showToast("Erro de comunicação com o C2.", "error"); }
                }

                async function quickCommand(type) {
                    if(!selectedAgentId) return;
                    showToast(`Executando macro: ${type}...`);
                    try {
                        const res = await fetch('/control/quick_command', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({agent_id: selectedAgentId, type})
                        });
                        const data = await res.json();
                        if(data.status === 'ok') {
                            const out = document.getElementById('terminal-output');
                            out.innerHTML += `<div class="text-sky-400 mt-2 font-black uppercase text-[9px]">[Macro: ${type}] > ${data.command}</div>`;
                            out.scrollTop = out.scrollHeight;
                        }
                    } catch(e) { showToast("C2 Error", "error"); }
                }

                function closeStatModal() {
                    document.getElementById('stat-detail-modal').classList.remove('active');
                }

                function showStatDetails(type) {
                    console.log("Stat clicked:", type);
                    const modal = document.getElementById('stat-detail-modal');
                    const title = document.getElementById('modal-title');
                    const iconBg = document.getElementById('modal-icon-bg');
                    const icon = document.getElementById('modal-icon');
                    const body = document.getElementById('modal-body');
                    
                    let html = '';
                    if(type === 'total') {
                        title.innerText = 'Endpoints Gerenciados';
                        iconBg.className = 'p-3 rounded-xl bg-sky-500/10 text-sky-500';
                        icon.setAttribute('data-lucide', 'monitor');
                        html = `<div class="space-y-3">
                            ${currentAgents.map(ag => `
                                <div class="p-4 rounded-xl bg-white/5 border border-white/5 flex justify-between items-center">
                                    <div class="flex items-center gap-3">
                                        <div class="w-2 h-2 rounded-full ${ag.status === 'online' ? 'bg-emerald-500' : 'bg-slate-500'}"></div>
                                        <span class="font-bold text-sm">${ag.hostname}</span>
                                    </div>
                                    <span class="text-[10px] text-slate-500 font-mono">${ag.platform}</span>
                                </div>
                            `).join('')}
                        </div>`;
                    } else if(type === 'online') {
                        title.innerText = 'Agentes em Tempo Real';
                        iconBg.className = 'p-3 rounded-xl bg-emerald-500/10 text-emerald-500';
                        icon.setAttribute('data-lucide', 'wifi');
                        const online = currentAgents.filter(a => a.status === 'online');
                        html = online.length > 0 ? `<div class="space-y-3">
                            ${online.map(ag => `
                                <div class="p-4 rounded-xl bg-emerald-500/5 border border-emerald-500/10 flex justify-between items-center">
                                    <span class="font-bold text-sm text-emerald-400">${ag.hostname}</span>
                                    <span class="text-[9px] px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-500 font-black">ONLINE</span>
                                </div>
                            `).join('')}
                        </div>` : '<div class="text-center py-10 text-slate-500 italic">Nenhum agente online no momento.</div>';
                    } else if(type === 'incidents') {
                        title.innerText = 'Ameaças Críticas';
                        iconBg.className = 'p-3 rounded-xl bg-rose-500/10 text-rose-500';
                        icon.setAttribute('data-lucide', 'shield-alert');
                        // We would ideally fetch more incident details, but for now we list the open ones from stats
                        html = `<div class="text-center py-10 text-slate-500 italic">Consulte o feed lateral para detalhes forenses. O Aegis SOC identificou incidentes críticos que requerem atenção imediata.</div>`;
                    } else if(type === 'health') {
                        title.innerText = 'Aegis Health Factor';
                        iconBg.className = 'p-3 rounded-xl bg-indigo-500/10 text-indigo-500';
                        icon.setAttribute('data-lucide', 'activity');
                        html = `<div class="space-y-6">
                            <div class="p-6 rounded-2xl bg-indigo-500/5 border border-indigo-500/10">
                                <h4 class="text-sm font-bold mb-2">Resumo de Postura</h4>
                                <p class="text-xs text-slate-400 leading-relaxed">O score de 98% indica um ambiente estável. 2% de depreciação devido a vulnerabilidades pendentes em 3 endpoints e 1 isolamento ativo.</p>
                            </div>
                            <div class="grid grid-cols-2 gap-4">
                                <div class="p-4 rounded-xl bg-white/5 border border-white/5">
                                    <div class="text-[10px] text-slate-500 mb-1">Patch Compliance</div>
                                    <div class="text-lg font-bold">94%</div>
                                </div>
                                <div class="p-4 rounded-xl bg-white/5 border border-white/5">
                                    <div class="text-[10px] text-slate-500 mb-1">Threat Block Rate</div>
                                    <div class="text-lg font-bold">100%</div>
                                </div>
                            </div>
                        </div>`;
                    }
                    
                    body.innerHTML = html;
                    lucide.createIcons();
                    modal.classList.add('active');
                }

                async function sendTerminalCommand() {
                    const input = document.getElementById('terminal-input');
                    const cmd = input.value.trim();
                    if(!cmd || !selectedAgentId) return;
                    const out = document.getElementById('terminal-output');
                    out.innerHTML += `<div class="text-sky-400 mt-3 font-mono">❯ ${cmd}</div>`;
                    input.value = '';
                    try {
                        const res = await fetch(`/control/command`, {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({agent_id: selectedAgentId, command: cmd})
                        });
                        const data = await res.json();
                        if(data.status === 'ok') out.innerHTML += `<div class="text-[10px] text-slate-500 italic">Comando aguardando heartbeat do agente...</div>`;
                        else out.innerHTML += `<div class="text-rose-400">Falha: ${data.error}</div>`;
                    } catch(e) { out.innerHTML += '<div class="text-rose-500">Erro de rede.</div>'; }
                    out.scrollTop = out.scrollHeight;
                }

                async function confirmUninstall(id) {
                    if(confirm("⚠️ AVISO: Esta ação enviará um comando de AUTO-DESTRUIÇÃO para o agente. Ele removerá todos os seus arquivos do host e encerrará a conexão. Deseja prosseguir?")) {
                        try {
                            const res = await fetch('/control/uninstall', {
                                method: 'POST',
                                headers: {'Content-Type': 'application/json'},
                                body: JSON.stringify({agent_id: id})
                            });
                            const data = await res.json();
                            if(data.status === 'ok') {
                                showToast("Ordem de desinstalação enviada!", "success");
                                closeAgentPanel();
                                fetchData();
                            } else {
                                showToast(data.error || "Falha ao solicitar desinstalação.", "error");
                            }
                        } catch(e) { showToast("C2 Connection Error", "error"); }
                    }
                }

                async function sendAIChat() {
                    const input = document.getElementById('ai-chat-input');
                    const msg = input.value.trim();
                    if(!msg) return;
                    const messages = document.getElementById('ai-chat-messages');
                    messages.innerHTML += `<div class="bg-indigo-500/10 p-4 rounded-2xl ml-4 text-xs text-slate-300 border border-indigo-500/20">${msg}</div>`;
                    input.value = '';
                    messages.scrollTop = messages.scrollHeight;
                    try {
                        const r = await fetch('/api/copilot/ask', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({message: msg})});
                        const d = await r.json();
                        messages.innerHTML += `<div class="bg-white/5 p-4 rounded-2xl mr-4 text-xs text-sky-200 border border-white/5">
                            <div class="flex items-center gap-2 mb-1"><i data-lucide="sparkles" class="w-3 h-3 text-purple-400"></i> <b class="uppercase text-[9px] tracking-widest">Aegis AI</b></div>
                            ${d.reply || 'Processando análise forense...'}
                        </div>`;
                        lucide.createIcons();
                        messages.scrollTop = messages.scrollHeight;
                    } catch(e) { messages.innerHTML += '<div class="text-rose-400 text-[10px]">Copilot offline.</div>'; }
                }

                setInterval(fetchData, 10000);
                fetchData();
            </script>
    """
    write_file("dashboard.html", apply_layout(dashboard_html, "Aegis SOC — Dashboard", active_item="dashboard"))

def rebuild_profile():
    profile_content = """
        <div class="max-w-4xl mx-auto py-10 px-6">
            <div class="flex items-center gap-6 mb-12">
                <div class="w-20 h-20 rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center text-3xl font-bold shadow-xl overflow-hidden border-2 border-white/10">
                    {% if user and user.avatar_url %}
                    <img src="{{ user.avatar_url }}" class="w-full h-full object-cover" alt="Profile">
                    {% else %}
                    {{ (user.display_name if user else user.username if user else 'A')[0].upper() }}
                    {% endif %}
                </div>
                <div>
                    <h1 class="text-3xl font-bold text-white">Configurações de Perfil</h1>
                    <p class="text-slate-400">Gerencie sua identidade e segurança na plataforma.</p>
                </div>
            </div>

            <div class="grid gap-6">
                <!-- Info -->
                <div class="hyper-glass p-8">
                    <h2 class="text-xl font-bold mb-6 flex items-center gap-2"><i data-lucide="user" class="w-5 h-5 text-sky-400"></i> Informações da Conta</h2>
                    <form action="/profile/update" method="POST" class="space-y-6">
                        {% if user %}
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div class="space-y-2">
                                <label class="text-sm text-slate-400">Nome de Exibição</label>
                                <input type="text" name="display_name" class="aegis-input" value="{{ user.display_name or '' }}" placeholder="Ex: Analista SOC 01">
                            </div>
                            <div class="space-y-2">
                                <label class="text-sm text-slate-400">Avatar URL (Foto de Perfil)</label>
                                <input type="url" name="avatar_url" class="aegis-input" value="{{ user.avatar_url or '' }}" placeholder="https://exemplo.com/sua-foto.jpg">
                            </div>
                        </div>
                        <div class="flex justify-end pt-4">
                            <button type="submit" class="aegis-btn-primary">SALVAR ALTERAÇÕES</button>
                        </div>
                        {% endif %}
                    </form>
                </div>

                <!-- Account Data (ReadOnly) -->
                <div class="hyper-glass p-8 opacity-80">
                    <h2 class="text-xl font-bold mb-6 flex items-center gap-2"><i data-lucide="database" class="w-5 h-5 text-slate-400"></i> Dados Globais</h2>
                    {% if user %}
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div class="space-y-2">
                            <label class="text-sm text-slate-400">Nome de Usuário</label>
                            <input type="text" class="aegis-input cursor-not-allowed bg-white/5" value="{{ user.username }}" disabled>
                        </div>
                        <div class="space-y-2">
                            <label class="text-sm text-slate-400">E-mail Cadastrado</label>
                            <input type="text" class="aegis-input cursor-not-allowed bg-white/5" value="{{ user.email or 'N/A' }}" disabled>
                        </div>
                    </div>
                    {% endif %}
                </div>

                <!-- Password -->
                <div class="hyper-glass p-8">
                    <h2 class="text-xl font-bold mb-6 flex items-center gap-2"><i data-lucide="lock" class="w-5 h-5 text-amber-500"></i> Segurança e Senha</h2>
                    <form action="/profile/change-password" method="POST" class="space-y-6">
                        <div class="space-y-2">
                            <label class="text-sm text-slate-400">Senha Atual</label>
                            <input type="password" name="current_password" class="aegis-input" required>
                        </div>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div class="space-y-2">
                                <label class="text-sm text-slate-400">Nova Senha</label>
                                <input type="password" name="new_password" class="aegis-input" required>
                            </div>
                            <div class="space-y-2">
                                <label class="text-sm text-slate-400">Confirmar Nova Senha</label>
                                <input type="password" name="confirm_password" class="aegis-input" required>
                            </div>
                        </div>
                        <div class="flex justify-end">
                            <button type="submit" class="aegis-btn-primary">Atualizar Senha</button>
                        </div>
                    </form>
                </div>

                <!-- MFA -->
                <div class="hyper-glass p-8 border-l-4 border-l-purple-500">
                    <div class="flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
                        <div>
                            <h2 class="text-xl font-bold mb-2">Autenticação de Dois Fatores (MFA)</h2>
                            <p class="text-sm text-slate-400 max-w-lg">Proteja sua conta com uma camada extra de segurança.</p>
                        </div>
                        <a href="/mfa/setup" class="aegis-btn-primary !bg-purple-600">
                            {{ 'Gerenciar MFA' if user and user.mfa_enabled else 'Ativar MFA Agora' }}
                        </a>
                    </div>
                </div>
            </div>
        </div>
    """
    write_file("profile.html", apply_layout(profile_content, "Aegis SOC — Perfil", active_item="profile"))

def rebuild_admin_users():
    content = """
            <header class="flex justify-between items-center mb-10">
                <div>
                    <h1 class="text-3xl font-bold tracking-tight">Gestão de Usuários</h1>
                    <p class="text-slate-400">Administre analistas e permissões do Aegis SOC.</p>
                </div>
            </header>

            <div class="space-y-8">
                <!-- Ativos -->
                <div class="hyper-glass overflow-hidden shadow-2xl">
                    <div class="px-6 py-4 border-b border-white/5 bg-white/5 flex justify-between items-center">
                        <h2 class="text-sm font-bold text-sky-400">Analistas Registrados</h2>
                        <span class="text-[10px] bg-sky-500/20 text-sky-400 px-2 py-0.5 rounded">{{ approved|length }}</span>
                    </div>
                    <table class="w-full text-left">
                        <thead class="bg-white/[0.03] border-b border-white/10 text-[10px] uppercase text-slate-500 tracking-widest font-bold">
                            <tr>
                                <th class="px-6 py-4">Usuário / Identidade</th>
                                <th class="px-6 py-4 text-center">Nível</th>
                                <th class="px-6 py-4 text-center">Status MFA</th>
                                <th class="px-6 py-4 text-right">Controle</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-white/5">
                            {% for u in approved %}
                            <tr class="hover:bg-white/[0.02] transition-colors group">
                                <td class="px-6 py-4">
                                    <div class="flex items-center gap-3">
                                        <div class="w-10 h-10 rounded-xl bg-indigo-500/10 text-indigo-400 flex items-center justify-center font-bold text-sm uppercase border border-indigo-500/20 group-hover:bg-indigo-500/20 transition-all">{{ u.username[0] }}</div>
                                        <div>
                                            <div class="text-sm font-bold text-white">{{ u.display_name or u.username }}</div>
                                            <div class="text-[10px] text-slate-500 font-mono">{{ u.email or 'admin@aegis.local' }}</div>
                                        </div>
                                    </div>
                                </td>
                                <td class="px-6 py-4 text-center">
                                    <span class="px-2 py-0.5 rounded-[4px] text-[9px] font-bold uppercase tracking-wider bg-slate-800 text-slate-400 border border-slate-700">
                                        {{ u.role }}
                                    </span>
                                </td>
                                <td class="px-6 py-4 text-center">
                                    {% if u.mfa_enabled %}
                                        <span class="text-emerald-500 flex items-center justify-center gap-1 text-[10px] font-bold"><i data-lucide="shield-check" class="w-3 h-3"></i> ATIVO</span>
                                    {% else %}
                                        <span class="text-slate-600 text-[10px] font-bold">INATIVO</span>
                                    {% endif %}
                                </td>
                                <td class="px-6 py-4 text-right">
                                    <div class="flex justify-end gap-2">
                                        <a href="/admin/users/{{ u.id }}/profile" class="p-2 hover:bg-sky-500/20 text-sky-400 rounded-lg transition-colors" title="Editar Perfil"><i data-lucide="user-cog" class="w-4 h-4"></i></a>
                                    </div>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <!-- Pendentes -->
                {% if pending %}
                <div class="hyper-glass overflow-hidden border-l-4 border-l-amber-500 shadow-2xl">
                    <div class="px-6 py-4 border-b border-white/5 bg-white/5">
                        <h2 class="text-sm font-bold text-amber-500 flex items-center gap-2 underline underline-offset-4">
                            <i data-lucide="clock" class="w-4 h-4"></i> Aguardando Aprovação
                        </h2>
                    </div>
                    <table class="w-full text-left">
                        <tbody class="divide-y divide-white/5">
                            {% for u in pending %}
                            <tr class="hover:bg-amber-500/5 transition-colors group">
                                <td class="px-6 py-4">
                                     <div class="flex items-center gap-3">
                                        <div class="w-10 h-10 rounded-xl bg-amber-500/10 text-amber-400 flex items-center justify-center font-bold text-sm uppercase">{{ u.username[0] }}</div>
                                        <div>
                                            <div class="text-sm font-bold text-white">{{ u.username }}</div>
                                            <div class="text-[10px] text-amber-500/50">Solicitação pendente</div>
                                        </div>
                                    </div>
                                </td>
                                <td class="px-6 py-4 text-right">
                                    <div class="flex justify-end gap-3 pr-2">
                                        <form action="/admin/users/{{ u.id }}/approve" method="POST">
                                            <button type="submit" class="p-2 bg-emerald-500/10 hover:bg-emerald-500/30 text-emerald-500 rounded-xl transition-all border border-emerald-500/20">
                                                <i data-lucide="user-check" class="w-5 h-5"></i>
                                            </button>
                                        </form>
                                        <form action="/admin/users/{{ u.id }}/reject" method="POST">
                                            <button type="submit" class="p-2 bg-rose-500/10 hover:bg-rose-500/30 text-rose-500 rounded-xl transition-all border border-rose-500/20">
                                                <i data-lucide="user-x" class="w-5 h-5"></i>
                                            </button>
                                        </form>
                                    </div>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% endif %}
            </div>
    """
    write_file("admin_users.html", apply_layout(content, "Aegis SOC — Admin", active_item="admin"))

def rebuild_admin_user_profile():
    content = """
        <div class="max-w-4xl mx-auto py-10 px-6">
            <div class="flex items-center gap-4 mb-10">
                 <a href="/admin/users" class="p-2 hover:bg-white/10 rounded-lg transition-colors text-slate-500 hover:text-white">
                    <i data-lucide="arrow-left" class="w-6 h-6"></i>
                </a>
                <h1 class="text-3xl font-bold text-white">Editar Profile: <span class="text-sky-500 underline">{{ target.username }}</span></h1>
            </div>

            <div class="grid gap-6">
                <div class="hyper-glass p-8">
                    <form action="/admin/users/{{ target.id }}/profile/update" method="POST" class="space-y-6">
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div class="space-y-2">
                                <label class="text-sm text-slate-400">Display Name</label>
                                <input type="text" name="display_name" class="aegis-input" value="{{ target.display_name or '' }}">
                            </div>
                            <div class="space-y-2">
                                <label class="text-sm text-slate-400">Email Contact</label>
                                <input type="email" name="email" class="aegis-input" value="{{ target.email or '' }}">
                            </div>
                            <div class="space-y-2">
                                <label class="text-sm text-slate-400">Role Authorization</label>
                                <select name="role" class="aegis-input">
                                    <option value="user" {% if target.role == 'user' %}selected{% endif %}>User (Restricted)</option>
                                    <option value="admin" {% if target.role == 'admin' %}selected{% endif %}>Admin (Full Control)</option>
                                    <option value="superadmin" {% if target.role == 'superadmin' %}selected{% endif %}>Super Admin</option>
                                </select>
                            </div>
                             <div class="space-y-2">
                                <label class="text-sm text-slate-400">MFA Status</label>
                                <div class="aegis-input opacity-60 flex items-center gap-2">
                                    <span class="w-2 h-2 rounded-full {{ 'bg-emerald-500' if target.mfa_enabled else 'bg-slate-600' }}"></span>
                                    {{ 'Ativo' if target.mfa_enabled else 'Desativado' }}
                                </div>
                            </div>
                        </div>
                        <div class="pt-4 flex justify-end gap-3">
                            <button type="submit" class="aegis-btn-primary">Update Authorization</button>
                        </div>
                    </form>
                </div>

                <div class="hyper-glass p-8 border-l-4 border-l-rose-500">
                    <h3 class="text-lg font-bold mb-4 flex items-center gap-2 text-rose-500"><i data-lucide="key" class="w-5 h-5"></i> Force Password Reset</h3>
                    <form action="/admin/users/{{ target.id }}/password" method="POST" class="flex gap-4">
                        <input type="password" name="new_password" class="aegis-input flex-1" placeholder="Enter new strong password..." required>
                        <button type="submit" class="aegis-btn-secondary border-rose-500/30 text-rose-500 hover:bg-rose-500/10">Reset Now</button>
                    </form>
                </div>
            </div>
        </div>
    """
    write_file("admin_user_profile.html", apply_layout(content, "Aegis SOC — Editar", active_item="admin"))

def rebuild_login():
    login_html = """
    <div class="min-h-screen flex items-center justify-center p-6 bg-deep-bg">
        <div class="w-full max-w-md">
            <div class="flex flex-col items-center mb-8">
                <div class="w-16 h-16 rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-700 flex items-center justify-center shadow-2xl border border-white/20 mb-4 group cursor-default">
                    <i data-lucide="shield" class="text-white w-8 h-8 group-hover:scale-110 transition-transform"></i>
                </div>
                <h1 class="text-3xl font-black tracking-tighter text-white">AEGIS <span class="text-sky-500">SOC</span></h1>
                <p class="text-slate-500 font-mono mt-1 uppercase tracking-[0.3em] text-[8px]">Cybersecurity Defense Unit</p>
            </div>

            <div class="space-y-6">
                <!-- Login Card -->
                <div id="login-card" class="hyper-glass p-8 space-y-6 relative overflow-hidden {{ 'hidden' if show_register else '' }}">
                    <h2 class="text-lg font-bold text-center tracking-tight">IDENTIFICAÇÃO SOC</h2>
                    
                    {% if error %}
                    <div class="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-500 text-xs font-bold flex items-center gap-3 animate-headShake">
                        <i data-lucide="alert-octagon" class="w-4 h-4"></i>
                        {{ error }}
                    </div>
                    {% endif %}
                    
                    {% if success %}
                    <div class="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-500 text-xs font-bold flex items-center gap-3 animate-bounce">
                        <i data-lucide="check-circle" class="w-4 h-4"></i>
                        {{ success }}
                    </div>
                    {% endif %}

                    <form action="/login" method="POST" class="space-y-5">
                        <div class="space-y-2">
                            <label class="text-[10px] text-slate-500 flex items-center gap-2 font-bold uppercase tracking-wider"><i data-lucide="user" class="w-3 h-3 text-sky-400"></i> Analista</label>
                            <input type="text" name="username" class="aegis-input" placeholder="seu.id" required autofocus>
                        </div>
                        <div class="space-y-2">
                            <label class="text-[10px] text-slate-500 flex items-center gap-2 font-bold uppercase tracking-wider"><i data-lucide="key" class="w-3 h-3 text-sky-400"></i> Password</label>
                            <input type="password" name="password" class="aegis-input" placeholder="••••••••" required>
                        </div>
                        <button type="submit" class="w-full aegis-btn-primary justify-center py-4 uppercase tracking-widest font-black text-sm">AUTENTICAR</button>
                    </form>
                    <div class="text-center pt-4 border-t border-white/5">
                        <button onclick="toggleAuth('register')" class="text-[10px] text-slate-500 hover:text-sky-400 transition-colors font-bold uppercase tracking-widest">NÃO POSSUI ACESSO? SOLICITAR CADASTRO</button>
                    </div>
                </div>

                <!-- Register Card -->
                <div id="register-card" class="hyper-glass p-8 space-y-6 relative overflow-hidden {{ '' if show_register else 'hidden' }}">
                    <div class="text-center">
                        <h2 class="text-lg font-bold tracking-tight">SOLICITAR ACESSO</h2>
                        <p class="text-[10px] text-slate-400 mt-1">O seu pedido passará por auditoria interna.</p>
                    </div>

                    {% if error %}
                    <div class="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-500 text-xs font-bold flex items-center gap-3 animate-headShake">
                        <i data-lucide="alert-octagon" class="w-4 h-4"></i>
                        {{ error }}
                    </div>
                    {% endif %}

                    <form action="/register" method="POST" class="space-y-4">
                        <div class="space-y-2">
                            <label class="text-[10px] text-slate-500 font-bold uppercase">ID de Usuário</label>
                            <input type="text" name="username" class="aegis-input" placeholder="ex: j.silva" required>
                        </div>
                        <div class="grid grid-cols-2 gap-4">
                            <div class="space-y-2">
                                <label class="text-[10px] text-slate-500 font-bold uppercase">Nome Completo</label>
                                <input type="text" name="display_name" class="aegis-input" placeholder="João Silva" required>
                            </div>
                            <div class="space-y-2">
                                <label class="text-[10px] text-slate-500 font-bold uppercase">Email</label>
                                <input type="email" name="email" class="aegis-input" placeholder="analista@empresa.com" required>
                            </div>
                        </div>
                        <div class="space-y-2">
                            <label class="text-[10px] text-slate-500 font-bold uppercase">Senha</label>
                            <input type="password" name="password" class="aegis-input" placeholder="Mínimo 8 caracteres" minlength="8" required>
                        </div>
                        <div class="space-y-2">
                            <label class="text-[10px] text-slate-500 font-bold uppercase">Justificativa de Acesso</label>
                            <textarea name="reason" class="aegis-input min-h-[80px]" placeholder="Setor, cargo e motivo do acesso..." required></textarea>
                        </div>
                        <button type="submit" class="w-full aegis-btn-primary !bg-emerald-600 justify-center py-4 uppercase tracking-widest font-black text-sm">ENVIAR SOLICITAÇÃO</button>
                    </form>
                    <div class="text-center pt-4 border-t border-white/5">
                        <button onclick="toggleAuth('login')" class="text-[10px] text-slate-500 hover:text-white transition-colors font-bold uppercase tracking-widest">VOLTAR AO LOGIN</button>
                    </div>
                </div>
            </div>

            <p class="text-center mt-8 text-slate-800 text-[10px] font-mono">AEGIS SOC EDR &bull; VERSION 2.0 &bull; 2026</p>
        </div>
    </div>

    <script>
        function toggleAuth(view) {
            const login = document.getElementById('login-card');
            const register = document.getElementById('register-card');
            if(view === 'register') {
                login.classList.add('hidden');
                register.classList.remove('hidden');
            } else {
                login.classList.remove('hidden');
                register.classList.add('hidden');
            }
        }
    </script>
    """
    write_file("login.html", apply_layout(login_html, "Aegis SOC — Login"))

def rebuild_history():
    history_html = """
            <header class="flex justify-between items-center mb-10">
                <div>
                    <h1 class="text-3xl font-bold tracking-tight">Histórico de Incidentes</h1>
                    <p class="text-slate-400">Log forense de todas as ameaças detectadas (Ativos e Removidos).</p>
                </div>
            </header>

            <div class="hyper-glass overflow-hidden shadow-2xl">
                <div class="overflow-x-auto">
                    <table class="w-full text-left border-collapse">
                        <thead>
                            <tr class="border-b border-white/5 bg-white/5 text-[10px] uppercase tracking-widest text-slate-500 font-bold">
                                <th class="p-4">Timestamp</th>
                                <th class="p-4">Título / Ameaça</th>
                                <th class="p-4">Endpoint</th>
                                <th class="p-4">Severidade</th>
                                <th class="p-4">Status</th>
                            </tr>
                        </thead>
                        <tbody id="history-table-body">
                            <!-- JS fill -->
                        </tbody>
                    </table>
                </div>
            </div>

            <script>
                async function fetchHistory() {
                    try {
                        const response = await fetch('/api/incidents?include_uninstalled=true&per_page=100');
                        const data = await response.json();
                        const tbody = document.getElementById('history-table-body');
                        tbody.innerHTML = '';

                        data.incidents.forEach(inc => {
                            const tr = document.createElement('tr');
                            tr.className = "border-b border-white/5 hover:bg-white/5 transition-colors group";
                            
                            const severityClass = inc.severity === 'CRITICAL' ? 'text-rose-500' : 
                                                 (inc.severity === 'HIGH' ? 'text-orange-500' : 'text-sky-400');
                            
                            const statusLabel = inc.status === 'OPEN' ? 
                                '<span class="px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-500 text-[9px] font-bold border border-rose-500/20">ABERTO</span>' :
                                '<span class="px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-500 text-[9px] font-bold border border-emerald-500/20">RESOLVIDO</span>';

                            const agentStatus = inc.agent_uninstalled ? 
                                '<span class="ml-2 px-1.5 py-0.5 bg-slate-800 text-slate-500 text-[8px] rounded border border-white/5">REMOVIDO</span>' : '';

                            tr.innerHTML = `
                                <td class="p-4 text-xs font-mono text-slate-500">${new Date(inc.created_at).toLocaleString()}</td>
                                <td class="p-4 font-bold text-sm text-slate-200">${inc.title}</td>
                                <td class="p-4">
                                    <div class="text-sm font-medium text-sky-400">${inc.hostname || 'Unknown'}</div>
                                    ${agentStatus}
                                </td>
                                <td class="p-4">
                                    <span class="text-[10px] font-black uppercase ${severityClass}">${inc.severity}</span>
                                </td>
                                <td class="p-4">${statusLabel}</td>
                            `;
                            tbody.appendChild(tr);
                        });
                    } catch (err) {
                        console.error("Erro ao buscar histórico:", err);
                    }
                }
                fetchHistory();
            </script>
    """
    write_file("history.html", apply_layout(history_html, "Aegis SOC — Histórico Forense", active_item="history"))

def rebuild_agent_detail():
    detail_html = """
            <nav class="flex items-center gap-2 mb-8 text-xs font-bold uppercase tracking-widest text-slate-500">
                <a href="/" class="hover:text-sky-400 transition-colors">Dashboard</a>
                <i data-lucide="chevron-right" class="w-3 h-3"></i>
                <span class="text-slate-300">Endpoint Detail</span>
                <i data-lucide="chevron-right" class="w-3 h-3"></i>
                <span class="text-sky-400">{{ agent.hostname }}</span>
            </nav>

            <header class="flex flex-col md:flex-row justify-between items-start md:items-center gap-6 mb-10">
                <div class="flex items-center gap-5">
                    <div class="w-16 h-16 rounded-3xl bg-gradient-to-br from-sky-500 to-indigo-600 flex items-center justify-center shadow-2xl shadow-sky-500/20">
                        <i data-lucide="monitor" class="text-white w-8 h-8"></i>
                    </div>
                    <div>
                        <div class="flex items-center gap-3">
                            <h1 class="text-4xl font-black tracking-tight text-white">{{ agent.hostname }}</h1>
                            <span id="agent-status-badge" class="px-3 py-1 rounded-full text-[10px] font-black uppercase border transition-all">
                                {{ agent.status }}
                            </span>
                        </div>
                        <p class="text-slate-400 mt-1 font-mono text-sm">UUID: {{ agent.id }} | Last Seen: {{ agent.last_seen }}</p>
                    </div>
                </div>
                <div class="flex gap-3">
                    <button onclick="fetchFullDetail()" class="aegis-btn-secondary flex items-center gap-2">
                        <i data-lucide="refresh-cw" class="w-4 h-4"></i> ATUALIZAR TELEMETRIA
                    </button>
                    <button onclick="confirmUninstall({{ agent.id }})" class="aegis-btn-primary !bg-rose-600 shadow-rose-500/20">
                        <i data-lucide="trash-2" class="w-4 h-4"></i> DESINSTALAR
                    </button>
                </div>
            </header>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-8">
                <!-- Main Info Bento -->
                <div class="md:col-span-2 space-y-8">
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-6">
                        <!-- System Card -->
                        <div class="hyper-glass p-8 group">
                            <h3 class="text-xs font-black text-slate-500 uppercase tracking-widest mb-6 flex items-center gap-2">
                                <i data-lucide="cpu" class="w-4 h-4"></i> Especificações do Sistema
                            </h3>
                            <div class="space-y-4">
                                <div class="flex justify-between items-center border-b border-white/5 pb-2">
                                    <span class="text-slate-400 text-sm">Plataforma</span>
                                    <span class="text-white font-mono text-sm font-bold">{{ agent.platform }}</span>
                                </div>
                                <div class="flex justify-between items-center border-b border-white/5 pb-2">
                                    <span class="text-slate-400 text-sm">Arquitetura</span>
                                    <span class="text-white font-mono text-sm" id="det-arch">---</span>
                                </div>
                                <div class="flex justify-between items-center">
                                    <span class="text-slate-400 text-sm">Path Execução</span>
                                    <span class="text-white font-mono text-[10px]" id="det-path">---</span>
                                </div>
                            </div>
                        </div>

                        <!-- Network Card -->
                        <div class="hyper-glass p-8 group border-sky-500/10">
                            <h3 class="text-xs font-black text-slate-500 uppercase tracking-widest mb-6 flex items-center gap-2">
                                <i data-lucide="globe" class="w-4 h-4 text-sky-400"></i> Interface de Rede
                            </h3>
                            <div class="space-y-4">
                                <div class="flex justify-between items-center border-b border-white/5 pb-2">
                                    <span class="text-slate-400 text-sm">IPv4 Local</span>
                                    <span class="text-sky-400 font-mono text-sm font-bold">{{ agent.ip_address }}</span>
                                </div>
                                <div class="flex justify-between items-center border-b border-white/5 pb-2">
                                    <span class="text-slate-400 text-sm">MAC Address</span>
                                    <span class="text-slate-300 font-mono text-[11px]">{{ agent.mac_address }}</span>
                                </div>
                                <div class="flex justify-between items-center">
                                    <span class="text-slate-400 text-sm">Status C2</span>
                                    <span class="text-emerald-500 font-black text-[10px] uppercase">Encriptado (AES-256)</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Process List / Large Data -->
                    <div class="hyper-glass p-8">
                        <div class="flex justify-between items-center mb-6">
                            <h3 class="text-xs font-black text-slate-500 uppercase tracking-widest flex items-center gap-2">
                                <i data-lucide="list" class="w-4 h-4 text-indigo-400"></i> Processos e Serviços Ativos
                            </h3>
                            <div class="flex gap-2">
                                <button onclick="runDetailCommand('PROCESSLIST')" class="text-[10px] font-black hover:text-white text-slate-500 transition-colors uppercase">Atualizar Lista</button>
                            </div>
                        </div>
                        <div class="rounded-2xl bg-black/40 border border-white/5 p-6 h-96 overflow-y-auto custom-scrollbar font-mono text-[11px] text-slate-400" id="det-process-terminal">
                            Aguardando requisição de telemetria de processos...
                        </div>
                    </div>
                    
                    <!-- Screenshot -->
                    <div class="hyper-glass p-8">
                         <h3 class="text-xs font-black text-slate-500 uppercase tracking-widest mb-6 flex items-center gap-2">
                            <i data-lucide="image" class="w-4 h-4 text-emerald-400"></i> Evidência Visual (Última Captura)
                        </h3>
                        <div class="rounded-2xl overflow-hidden border border-white/10 bg-black/20 aspect-video flex items-center justify-center relative group">
                            <img id="det-screenshot" src="" class="w-full h-full object-contain hidden group-hover:scale-105 transition-transform duration-700" />
                            <div id="det-no-screenshot" class="text-slate-600 text-xs italic flex flex-col items-center gap-3">
                                <i data-lucide="camera-off" class="w-12 h-12 opacity-20"></i>
                                Nenhuma captura disponível
                            </div>
                            <button onclick="runSoarAction('screenshot')" class="absolute bottom-6 right-6 aegis-btn-primary opacity-0 group-hover:opacity-100 transition-opacity">CAPTURAR AGORA</button>
                        </div>
                    </div>
                </div>

                <!-- Forensic / Commands Sidebar -->
                <div class="space-y-8">
                    <!-- Control Panel -->
                    <div class="hyper-glass p-8 border-rose-500/10">
                        <h3 class="text-xs font-black text-rose-500 uppercase tracking-widest mb-6 flex items-center gap-2">
                            <i data-lucide="zap" class="w-4 h-4"></i> Comandos de Contenção
                        </h3>
                        <div class="grid grid-cols-1 gap-4">
                            <button id="det-btn-isolate" onclick="toggleIsolate()" class="w-full p-4 rounded-xl border border-white/5 bg-white/5 hover:bg-rose-500/10 hover:border-rose-500/30 transition-all flex items-center gap-4 group">
                                <div class="p-2 rounded-lg bg-rose-500/10 text-rose-500 group-hover:scale-110 transition-transform"><i data-lucide="lock" class="w-5 h-5"></i></div>
                                <div class="text-left">
                                    <div class="text-xs font-black text-white uppercase">Host Isolation</div>
                                    <div class="text-[9px] text-slate-500">Corta tráfego exceto com C2</div>
                                </div>
                            </button>
                            <button onclick="runSoarAction('force_logs')" class="w-full p-4 rounded-xl border border-white/5 bg-white/5 hover:bg-sky-500/10 hover:border-sky-500/30 transition-all flex items-center gap-4 group">
                                <div class="p-2 rounded-lg bg-sky-500/10 text-sky-400 group-hover:scale-110 transition-transform"><i data-lucide="database" class="w-5 h-5"></i></div>
                                <div class="text-left">
                                    <div class="text-xs font-black text-white uppercase">Coletar Artefatos</div>
                                    <div class="text-[9px] text-slate-500">Dump de logs e registros</div>
                                </div>
                            </button>
                        </div>
                    </div>

                    <!-- Incident Feed for this Agent -->
                    <div class="hyper-glass p-8">
                        <h3 class="text-xs font-black text-slate-500 uppercase tracking-widest mb-6 flex items-center gap-2">
                            <i data-lucide="history" class="w-4 h-4 text-amber-500"></i> Histórico do Endpoint
                        </h3>
                        <div id="det-incidents-feed" class="space-y-4 max-h-[400px] overflow-y-auto pr-2 custom-scrollbar text-xs">
                            <!-- JS populate -->
                            <div class="text-center py-10 text-slate-600 italic">Carregando histórico...</div>
                        </div>
                    </div>

                    <!-- C2 Terminal Detail -->
                    <div class="hyper-glass p-8 bg-black/20">
                        <h3 class="text-xs font-black text-sky-400 uppercase tracking-widest mb-4 flex items-center gap-2">
                            <i data-lucide="terminal" class="w-4 h-4"></i> Direct C2 Shell
                        </h3>
                        <div class="rounded-xl bg-black border border-white/5 p-4 h-48 font-mono text-[10px] text-emerald-500/80 overflow-y-auto mb-4 custom-scrollbar" id="det-terminal-out">
                            Handshake estabelecido. Pronto para comandos.
                        </div>
                        <div class="flex gap-2">
                            <input type="text" id="det-terminal-in" class="aegis-input !py-2 !text-[10px] !bg-black" placeholder="Command..." onkeydown="if(event.key==='Enter')sendDetCommand()">
                            <button onclick="sendDetCommand()" class="p-2 bg-sky-600 rounded-lg text-white hover:bg-sky-500 transition-colors"><i data-lucide="send" class="w-3 h-3"></i></button>
                        </div>
                    </div>
                </div>
            </div>

            <script>
                const currentId = {{ agent.id }};
                let lastTimestamp = null;

                async function fetchFullDetail() {
                    try {
                        const res = await fetch(`/api/agent/${currentId}/detail`);
                        if(res.ok) {
                            const data = await res.json();
                            const ag = data.agent;
                            
                            // Update Status Badge
                            const badge = document.getElementById('agent-status-badge');
                            badge.innerText = ag.status;
                            badge.className = `px-3 py-1 rounded-full text-[10px] font-black uppercase border transition-all ${
                                ag.status === 'online' ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' : 
                                ag.status === 'isolated' ? 'bg-rose-500/10 text-rose-500 border-rose-500/20 shadow-[0_0_15px_rgba(244,63,94,0.3)]' : 
                                'bg-slate-500/10 text-slate-500 border-slate-500/20'
                            }`;

                            // Isolation button update
                            const isoBtn = document.getElementById('det-btn-isolate');
                            if(ag.isolation_active) {
                                isoBtn.onclick = () => runSoarAction('unisolate');
                                isoBtn.querySelector('.text-white').innerText = "Remove Isolation";
                                isoBtn.querySelector('.bg-rose-500/10').className = "p-2 rounded-lg bg-emerald-500/10 text-emerald-500 group-hover:scale-110 transition-transform";
                                isoBtn.querySelector('i').setAttribute('data-lucide', 'shield-off');
                            } else {
                                isoBtn.onclick = () => runSoarAction('isolate');
                                isoBtn.querySelector('.text-white').innerText = "Host Isolation";
                                isoBtn.querySelector('.bg-emerald-500/10')?.classList.replace('bg-emerald-500/10', 'bg-rose-500/10');
                                isoBtn.querySelector('.text-emerald-500')?.classList.replace('text-emerald-500', 'text-rose-500');
                                isoBtn.querySelector('i').setAttribute('data-lucide', 'lock');
                            }

                            // Extra Info
                            document.getElementById('det-arch').innerText = data.extra_data?.arch || '---';
                            document.getElementById('det-path').innerText = data.extra_data?.execution_path || '---';

                            // Screenshot
                            const img = document.getElementById('det-screenshot');
                            const placeholder = document.getElementById('det-no-screenshot');
                            if(ag.last_screenshot) {
                                const snapRes = await fetch(`/api/screenshot/${currentId}`);
                                if(snapRes.ok) {
                                    const snapData = await snapRes.json();
                                    img.src = `data:image/png;base64,${snapData.screenshot_b64}`;
                                    img.classList.remove('hidden');
                                    placeholder.classList.add('hidden');
                                }
                            }

                            // Incidents
                            const feed = document.getElementById('det-incidents-feed');
                            if(data.open_incidents && data.open_incidents.length > 0) {
                                feed.innerHTML = data.open_incidents.map(inc => `
                                    <div class="p-3 rounded-lg bg-white/5 border border-white/5 space-y-2">
                                        <div class="flex justify-between items-center">
                                            <span class="font-bold text-slate-200">${inc.title}</span>
                                            <span class="text-[8px] px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-500 border border-rose-500/20">${inc.severity}</span>
                                        </div>
                                        <p class="text-slate-500 text-[10px] leading-relaxed">${inc.description}</p>
                                        <div class="text-[8px] text-slate-600 font-mono">${new Date(inc.created_at).toLocaleString()}</div>
                                    </div>
                                `).join('');
                            } else {
                                feed.innerHTML = '<div class="text-center py-10 text-slate-600 italic">Nenhum incidente ativo para este endpoint.</div>';
                            }

                            // Terminal results
                            if(data.last_command_result && data.agent.command_result_time !== lastTimestamp) {
                                lastTimestamp = data.agent.command_result_time;
                                const out = document.getElementById('det-terminal-out');
                                const resData = data.last_command_result;
                                out.innerHTML += `<div class="mt-2 text-slate-500 border-t border-white/5 pt-2">
                                    <span class="text-sky-400">OUTPUT [${new Date(lastTimestamp).toLocaleTimeString()}] ></span><br>
                                    <pre class="whitespace-pre-wrap">${resData.output || 'No output'}</pre>
                                </div>`;
                                out.scrollTop = out.scrollHeight;
                                
                                // Specific for process list update
                                if(resData.command === 'PROCESSLIST' || resData.command === 'NETSTAT' || resData.command === 'SYSINFO' || resData.command === 'USERS') {
                                     document.getElementById('det-process-terminal').innerHTML = `<pre class="whitespace-pre-wrap text-[10px]">${resData.output}</pre>`;
                                }
                            }
                            
                            lucide.createIcons();
                        }
                    } catch(err) { console.error("Forensic Fetch Error:", err); }
                }

                async function runSoarAction(action) {
                    try {
                        const res = await fetch(`/api/soar/${currentId}`, {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({action})
                        });
                        if(res.ok) fetchFullDetail();
                    } catch(e) {}
                }

                async function runDetailCommand(type) {
                    try {
                        await fetch('/control/quick_command', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({agent_id: currentId, type})
                        });
                        document.getElementById('det-process-terminal').innerHTML = `<div class="flex items-center gap-2 text-sky-400 animate-pulse"><i data-lucide="loader" class="w-4 h-4"></i> REQUISITANDO DADOS AO AGENTE...</div>`;
                        lucide.createIcons();
                    } catch(e) {}
                }

                async function sendDetCommand() {
                    const input = document.getElementById('det-terminal-in');
                    const cmd = input.value;
                    if(!cmd) return;
                    input.value = '';
                    try {
                        await fetch('/control/command', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({agent_id: currentId, command: cmd})
                        });
                        const out = document.getElementById('det-terminal-out');
                        out.innerHTML += `<div class="text-white mt-1 font-bold">> ${cmd}</div>`;
                        out.scrollTop = out.scrollHeight;
                    } catch(e) {}
                }

                // Poll detail every 3s
                fetchFullDetail();
                setInterval(fetchFullDetail, 3000);
            </script>
    """
    write_file("agent_detail.html", apply_layout(detail_html, "Aegis Forensic — {{ agent.hostname }}", active_item="dashboard"))

def rebuild_mfa_flow():
    # Setup MFA
    mfa_setup = """
    <div class="max-w-2xl mx-auto py-20 px-6">
        <div class="hyper-glass p-10 text-center space-y-8 border-t-4 border-t-indigo-600">
            <h1 class="text-3xl font-black">PROTEÇÃO EXTRA</h1>
            <p class="text-slate-400 text-sm">Escaneie o código abaixo com seu app autenticador nível SOC.</p>
            <div class="bg-white p-6 rounded-2xl inline-block shadow-2xl border-4 border-indigo-600/50">
                <img src="/mfa/qr" alt="MFA QR" class="w-48 h-48">
            </div>
            <div class="space-y-4 max-w-sm mx-auto">
                <p class="text-[10px] text-slate-500 font-mono italic">Manual Key: {{ secret }}</p>
                <form action="/mfa/confirm" method="POST" class="space-y-4">
                    <input type="text" name="code" class="aegis-input text-center text-3xl font-black placeholder-slate-800" placeholder="000 000" maxlength="6" required>
                    <button type="submit" class="w-full aegis-btn-primary justify-center">VALIDAR E ATIVAR</button>
                    <a href="/profile" class="block text-xs text-slate-600 hover:text-white transition-colors uppercase font-bold tracking-widest">CANCELAR</a>
                </form>
            </div>
        </div>
    </div>
    """
    write_file("mfa_setup.html", apply_layout(mfa_setup, "Aegis SOC — Setup MFA"))

    # Verify MFA
    mfa_verify = """
    <div class="min-h-screen flex items-center justify-center p-6">
        <div class="w-full max-w-md">
            <div class="hyper-glass p-10 text-center space-y-8 border-b-4 border-b-sky-500 shadow-2xl">
                <div class="mx-auto w-16 h-16 rounded-3xl bg-sky-500/10 flex items-center justify-center text-sky-500 border border-sky-500/20">
                    <i data-lucide="shield-check" class="w-8 h-8"></i>
                </div>
                <div>
                    <h1 class="text-2xl font-black text-white">AUTENTICAÇÃO MFA</h1>
                    <p class="text-[11px] text-slate-400 mt-2 uppercase tracking-widest">Segunda camada de segurança exigida.</p>
                </div>

                {% if error %}
                <div class="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-500 text-xs font-bold flex items-center gap-3">
                    <i data-lucide="alert-octagon" class="w-4 h-4"></i>
                    {{ error }}
                </div>
                {% endif %}

                <form action="/mfa/verify" method="POST" class="space-y-6">
                    <input type="text" name="code" class="aegis-input text-center text-3xl font-black placeholder-slate-900" placeholder="000000" maxlength="6" required autofocus>
                    <button type="submit" class="w-full aegis-btn-primary justify-center py-4 font-black">VALIDAR TOKEN</button>
                    <div class="pt-4 border-t border-white/5">
                        <a href="/mfa/recovery" class="text-[10px] text-slate-500 hover:text-rose-400 transition-colors font-bold">PROBLEMAS COM O APP? USAR RECOV CODE</a>
                    </div>
                </form>
            </div>
        </div>
    </div>
    """
    write_file("mfa_verify.html", apply_layout(mfa_verify, "Aegis SOC — Autenticação MFA"))

    # Recovery
    mfa_recovery = """
    <div class="min-h-screen flex items-center justify-center p-6">
        <div class="w-full max-w-md">
            <div class="hyper-glass p-10 text-center space-y-8 border-l-4 border-rose-600 shadow-2xl">
                <div class="mx-auto w-16 h-16 rounded-3xl bg-rose-500/10 flex items-center justify-center text-rose-500 border border-rose-500/20">
                    <i data-lucide="life-buoy" class="w-8 h-8"></i>
                </div>
                <div>
                    <h1 class="text-2xl font-black text-white">RECOV PROTOCOL</h1>
                    <p class="text-xs text-slate-400 mt-2">Insira um código de recuperação de emergência.</p>
                </div>

                {% if error %}
                <div class="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-500 text-xs font-bold flex items-center gap-3">
                    <i data-lucide="alert-octagon" class="w-4 h-4"></i>
                    {{ error }}
                </div>
                {% endif %}

                <form action="/mfa/recovery" method="POST" class="space-y-6">
                    <input type="text" name="recovery_code" class="aegis-input text-center font-mono text-xl tracking-widest uppercase" placeholder="XXXXXXXX" maxlength="8" required autofocus>
                    <button type="submit" class="w-full aegis-btn-primary !bg-rose-600 justify-center py-4 font-black">BYPASS MFA</button>
                    <div class="pt-4">
                        <a href="/login" class="text-[10px] text-slate-500 hover:text-white transition-colors font-bold">VOLTAR AO LOGIN INTEGRADO</a>
                    </div>
                </form>
            </div>
        </div>
    </div>
    """
    write_file("mfa_recovery.html", apply_layout(mfa_recovery, "Aegis SOC — Recuperação"))

if __name__ == "__main__":
    rebuild_dashboard()
    rebuild_agent_detail()
    rebuild_history()
    rebuild_profile()
    rebuild_login()
    rebuild_admin_users()
    rebuild_admin_user_profile()
    rebuild_mfa_flow()
    print("Hyper-Glass UI Unified & Refactored Successfully!")
