import os
import re

TEMPLATES_DIR = "server/templates"

GLOBAL_CSS = """
    /* Aegis Next-Gen Deep Space & Neon Theme */
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
    
    :root {
        --deep-space: #0B0F19;
        --card-bg: rgba(17, 24, 39, 0.6);
        --neon-sky: #0EA5E9;
        --neon-emerald: #10B981;
        --neon-rose: #F43F5E;
        --border-subtle: rgba(255, 255, 255, 0.05);
    }

    * { box-sizing: border-box; font-family: 'Outfit', sans-serif; }
    
    body {
        background-color: var(--deep-space);
        background-image: radial-gradient(circle at 15% 50%, rgba(14, 165, 233, 0.06), transparent 25%), 
                          radial-gradient(circle at 85% 30%, rgba(16, 185, 129, 0.04), transparent 25%);
        color: #E2E8F0;
        min-height: 100vh;
        overflow-x: hidden;
        margin: 0;
    }

    /* Scrollbars */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 6px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--neon-sky); }

    /* Bento Cards & Glassmorphism */
    .bento-card {
        background: var(--card-bg);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid var(--border-subtle);
        border-radius: 16px;
        transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    }
    .bento-card:hover { 
        transform: translateY(-4px); 
        border-color: rgba(14, 165, 233, 0.3);
        box-shadow: 0 12px 30px rgba(14, 165, 233, 0.15);
    }

    /* Base Input fixes (To prevent white background/text bugs) */
    .aegis-input {
        background: rgba(15, 23, 42, 0.8) !important;
        border: 1px solid rgba(255,255,255,0.1) !important;
        color: #F8FAFC !important;
        border-radius: 10px;
        padding: 10px 14px;
        font-size: 14px;
        width: 100%;
        outline: none;
        transition: all 0.3s ease;
        color-scheme: dark; /* AutoFill Support */
    }
    .aegis-input:focus {
        border-color: var(--neon-sky) !important;
        box-shadow: 0 0 0 3px rgba(14, 165, 233, 0.15) !important;
    }

    /* Buttons */
    .btn-neon {
        background: linear-gradient(135deg, #0ea5e9, #0284c7);
        color: white;
        font-weight: 500;
        padding: 10px 20px;
        border-radius: 10px;
        border: none;
        cursor: pointer;
        font-size: 14px;
        transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        box-shadow: 0 4px 15px rgba(14,165,233,0.3);
    }
    .btn-neon:hover:not(:disabled) {
        transform: translateY(-2px) scale(1.02);
        box-shadow: 0 8px 25px rgba(14,165,233,0.5);
    }
    .btn-danger-neon {
        background: rgba(244, 63, 94, 0.1);
        border: 1px solid rgba(244, 63, 94, 0.3);
        color: #FDA4AF;
        font-weight: 600;
        padding: 10px 20px;
        border-radius: 10px;
        transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    }
    .btn-danger-neon:hover {
        background: rgba(244, 63, 94, 0.2);
        border-color: var(--neon-rose);
        box-shadow: 0 0 20px rgba(244, 63, 94, 0.4);
        transform: translateY(-2px);
    }

    /* Toasts */
    #toast-container { position: fixed; top: 24px; right: 24px; z-index: 9999; display: flex; flex-direction: column; gap: 12px; pointer-events: none; }
    .toast { background: rgba(15, 23, 42, 0.95); backdrop-filter: blur(16px); border-radius: 12px; padding: 14px 24px; color: #fff; font-size: 13px; font-weight: 500; display: flex; align-items: center; gap: 12px; box-shadow: 0 10px 40px rgba(0,0,0,0.5); border: 1px solid rgba(255,255,255,0.05); transform: translateX(120%) scale(0.9); transition: all 0.5s cubic-bezier(0.68, -0.55, 0.265, 1.55); opacity: 0; pointer-events: auto; }
    .toast.show { transform: translateX(0) scale(1); opacity: 1; }
    .toast-error { border-left: 4px solid var(--neon-rose); }
    .toast-success { border-left: 4px solid var(--neon-emerald); }
    .toast-warning { border-left: 4px solid #F59E0B; }
"""

def read_file(name):
    p = os.path.join(TEMPLATES_DIR, name)
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as f:
            return f.read()
    return ""

def write_file(name, txt):
    p = os.path.join(TEMPLATES_DIR, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(txt)

def fix_profile_pages():
    for name in ["admin_user_profile.html", "profile.html", "mfa_setup.html"]:
        txt = read_file(name)
        if not txt: continue
        
        # Replace the entire style tag with our new global aesthetics
        txt = re.sub(r'<style>.*?</style>', f'<style>{GLOBAL_CSS}</style>', txt, flags=re.DOTALL)
        
        # We need to make sure the body is clean
        if '<body class=' in txt:
            txt = re.sub(r'<body class=".*?">', '<body>', txt)
        
        # Re-center and pad the main content
        txt = txt.replace('class="max-w-2xl mx-auto space-y-5"', 'class="max-w-3xl mx-auto space-y-6 pt-10 px-4"')
        txt = txt.replace('<main class="max-w-2xl mx-auto p-6 space-y-6 relative z-10 mt-10">', '<main class="max-w-3xl mx-auto p-6 space-y-6 relative z-10 mt-10 px-4">')
        
        # Swap classes for inputs and cards
        txt = txt.replace('class="card p-6"', 'class="bento-card p-8"')
        txt = txt.replace('class="input-field"', 'class="aegis-input"')
        txt = txt.replace('class="btn-primary"', 'class="btn-neon"')
        txt = txt.replace('class="btn-primary whitespace-nowrap"', 'class="btn-neon"')
        txt = txt.replace('class="btn-danger"', 'class="btn-danger-neon"')
        
        # Check toast container
        if 'id="toast-container"' not in txt:
            txt = txt.replace('<body>', '<body>\n    <div id="toast-container"></div>')

        # Toasts js logic if not present
        if 'function showToast' not in txt:
            toast_script = """
            <script>
            function showToast(message, type = 'info') {
              const container = document.getElementById('toast-container');
              if (!container) return;
              if (message.includes('[ERRO]') && type === 'info') type = 'error';
              message = message.replace('[ERRO]', '').trim();
              const toast = document.createElement('div');
              let typeClass = '';
              let icon = 'ℹ️';
              if (type === 'error' || type === 'danger') { typeClass = 'toast-error'; icon = '❌'; }
              if (type === 'success') { typeClass = 'toast-success'; icon = '✅'; }
              if (type === 'warning') { typeClass = 'toast-warning'; icon = '⚠️'; }
              toast.className = `toast ${typeClass}`;
              toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;
              container.appendChild(toast);
              setTimeout(() => toast.classList.add('show'), 10);
              setTimeout(() => { toast.classList.remove('show'); setTimeout(() => toast.remove(), 600); }, 5000);
            }
            </script>
            """
            txt = txt.replace('</body>', f'{toast_script}\n</body>')

        write_file(name, txt)

def rewrite_login():
    name = "login.html"
    txt = read_file(name)
    if not txt: return
    
    txt = re.sub(r'<style>.*?</style>', f'<style>{GLOBAL_CSS}</style>', txt, flags=re.DOTALL)
    
    # Modern Login Layout
    txt = re.sub(r'<div class="min-h-screen bg-transparent flex items-center justify-center">', '<div class="min-h-screen flex items-center justify-center relative overlow-hidden">', txt)
    
    # Login Card
    txt = txt.replace('class="glass p-10 rounded-2xl w-full max-w-md mx-4 fade-up relative overflow-hidden shadow-2xl"', 'class="bento-card p-10 w-full max-w-md mx-4 relative z-10"')
    
    # Logo text
    txt = txt.replace('class="text-2xl font-black text-center mb-8 glow-text tracking-wide"', 'class="text-3xl font-bold text-center mb-8 text-white tracking-wide"')
    
    # Inputs & Buttons
    txt = re.sub(r'class="w-full bg-\[\#161b24\].*?transition-all"', 'class="aegis-input"', txt)
    txt = re.sub(r'class="w-full bg-gradient-to-r.*?px-4 py-3"', 'class="w-full btn-neon py-3 text-base"', txt)
    
    # Toast container
    if 'id="toast-container"' not in txt:
        txt = txt.replace('<body>', '<body>\n    <div id="toast-container"></div>')

    write_file(name, txt)

if __name__ == "__main__":
    fix_profile_pages()
    rewrite_login()
    print("Secondary pages updated to Next-Gen Deep Space logic.")
