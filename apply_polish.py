import os
import re

TEMPLATES_DIR = "server/templates"

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
    input_tw = 'w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500 transition-all placeholder-slate-500'
    btn_tw = 'bg-gradient-to-r from-sky-500 to-blue-600 text-white font-medium rounded-lg px-4 py-2 shadow-lg shadow-sky-500/30 hover:-translate-y-0.5 hover:scale-105 hover:shadow-sky-500/50 transition-all cursor-pointer inline-flex items-center justify-center'
    
    for name in ["admin_user_profile.html", "profile.html", "mfa_setup.html", "admin_users.html"]:
        txt = read_file(name)
        if not txt: continue
        
        # Strip old input classes and replace with pure tailwind
        txt = txt.replace('class="aegis-input"', f'class="{input_tw}"')
        txt = txt.replace('class="input-field"', f'class="{input_tw}"')
        txt = txt.replace('class="input-field opacity-50"', f'class="{input_tw} opacity-50 cursor-not-allowed"')
        
        # Replace buttons
        txt = txt.replace('class="btn-neon"', f'class="{btn_tw}"')
        txt = txt.replace('class="btn-primary"', f'class="{btn_tw}"')
        txt = txt.replace('class="btn-primary whitespace-nowrap"', f'class="{btn_tw} whitespace-nowrap"')
        
        write_file(name, txt)

def update_dashboard():
    name = "dashboard.html"
    txt = read_file(name)
    if not txt: return
    
    # 1. Add Background animation and Icon keyframes
    anim_css = """
    /* Enhancements & Animations */
    @keyframes floatLight {
        0% { transform: translateY(0px) rotate(0deg); opacity: 0.8; }
        50% { transform: translateY(-20px) rotate(2deg); opacity: 0.4; }
        100% { transform: translateY(0px) rotate(0deg); opacity: 0.8; }
    }
    @keyframes pulseSoft {
        0%, 100% { transform: scale(1); opacity: 1; }
        50% { transform: scale(1.05); opacity: 0.7; }
    }
    .bg-animated {
        position: fixed; top: -50%; left: -50%; width: 200%; height: 200%;
        background-image: 
            radial-gradient(circle at 50% 50%, rgba(14, 165, 233, 0.05) 0%, transparent 40%),
            radial-gradient(circle at 20% 80%, rgba(168, 85, 247, 0.05) 0%, transparent 40%);
        animation: rotateBg 60s linear infinite;
        z-index: -1; pointer-events: none;
    }
    @keyframes rotateBg { 100% { transform: rotate(360deg); } }
    
    .icon-animated { animation: floatLight 4s ease-in-out infinite; }
    .side-icon { transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275); }
    .side-icon:hover i { animation: pulseSoft 1s infinite; fill: rgba(14,165,233,0.2); }

    /* Floating Chat Bubble CSS */
    #floating-chat-bubble {
        position: fixed; bottom: 30px; right: 30px; z-index: 100;
        width: 60px; height: 60px; border-radius: 50%;
        background: linear-gradient(135deg, #a855f7, #6366f1);
        box-shadow: 0 10px 30px rgba(99, 102, 241, 0.4);
        cursor: pointer; display: flex; align-items: center; justify-content: center;
        transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275); color: white;
    }
    #floating-chat-bubble:hover { transform: scale(1.1) translateY(-5px); box-shadow: 0 15px 40px rgba(99, 102, 241, 0.6); }
    
    #floating-chat-window {
        position: fixed; bottom: 100px; right: 30px; z-index: 99;
        width: 350px; height: 450px; border-radius: 20px;
        background: rgba(15, 23, 42, 0.95); backdrop-filter: blur(20px);
        border: 1px solid rgba(168, 85, 247, 0.2);
        box-shadow: 0 20px 50px rgba(0,0,0,0.5);
        display: flex; flex-direction: column;
        transform: translateY(20px) scale(0.9); opacity: 0; pointer-events: none;
        transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    }
    #floating-chat-window.open { transform: translateY(0) scale(1); opacity: 1; pointer-events: auto; }
"""
    if "/* Enhancements & Animations */" not in txt:
        txt = txt.replace("</style>", anim_css + "\n</style>")
        txt = txt.replace("<body>", "<body>\n  <div class=\"bg-animated\"></div>")

    # 2. Add Floating Chat HTML to body end
    floating_chat_html = """
  <!-- FLOATING CHAT -->
  <div id="floating-chat-bubble" onclick="toggleChat()">
      <i data-lucide="message-circle" class="w-8 h-8"></i>
  </div>

  <div id="floating-chat-window">
      <div class="flex items-center justify-between p-4 border-b border-white/10 bg-gradient-to-r from-purple-500/20 to-indigo-500/20 rounded-t-20">
          <div class="flex items-center gap-2">
              <i data-lucide="bot" class="w-5 h-5 text-purple-400"></i>
              <h3 class="text-sm font-bold text-white">Aegis AI Copilot</h3>
          </div>
          <button onclick="toggleChat()" class="text-slate-400 hover:text-white"><i data-lucide="x" class="w-4 h-4"></i></button>
      </div>
      <div id="floating-chat-messages" class="flex-1 overflow-y-auto p-4 space-y-3 text-sm text-slate-300">
          <p class="text-slate-500 text-xs italic text-center">A IA está pronta para analisar ameaças.</p>
      </div>
      <div class="p-3 border-t border-white/10 bg-black/20 rounded-b-20 flex gap-2">
          <input type="text" id="floating-chat-input" class="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-purple-500" placeholder="Pergunte à IA..." onkeydown="if(event.key==='Enter')sendFloatingChat()">
          <button onclick="sendFloatingChat()" class="bg-gradient-to-r from-purple-500 to-indigo-500 text-white p-2 rounded-lg hover:scale-105 transition-transform"><i data-lucide="send" class="w-4 h-4"></i></button>
      </div>
  </div>
"""
    if 'id="floating-chat-bubble"' not in txt:
        txt = txt.replace("</body>", floating_chat_html + "\n</body>")

    # 3. Add toggleChat JS and rewrite sendChat logic
    js_logic = """
    let chatOpen = false;
    function toggleChat() {
        chatOpen = !chatOpen;
        const w = document.getElementById('floating-chat-window');
        const b = document.querySelector('#floating-chat-bubble i');
        if(chatOpen) { w.classList.add('open'); b.setAttribute('data-lucide', 'x'); }
        else { w.classList.remove('open'); b.setAttribute('data-lucide', 'message-circle'); }
        lucide.createIcons();
    }

    async function sendFloatingChat() {
        const i = document.getElementById('floating-chat-input');
        const m = i.value.trim();
        if(!m) return;
        const cm = document.getElementById('floating-chat-messages');
        cm.innerHTML += `<div class="bg-slate-800/80 p-3 rounded-lg ml-6 text-white border border-slate-700">${m}</div>`;
        i.value = '';
        cm.scrollTop = cm.scrollHeight;
        
        try {
            const r = await fetch('/api/copilot/ask', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({message: m})});
            const d = await r.json();
            cm.innerHTML += `<div class="bg-purple-900/40 p-3 rounded-lg mr-6 text-sky-100 border border-purple-500/30"><strong>AI:</strong> ${d.reply || 'Erro cognitivo.'}</div>`;
            cm.scrollTop = cm.scrollHeight;
        } catch(e) {
            cm.innerHTML += `<div class="text-rose-400 text-xs text-center">Erro ao contatar IA.</div>`;
        }
    }
    """
    if "function toggleChat" not in txt:
        txt = txt.replace("</body>", "<script>\\n" + js_logic + "\\n</script>\\n</body>")

    # 4. Remove the old AI Chat from the grid
    # Search for the old chat block and remove it carefully
    old_chat_block = r'<!-- Quick Actions / AI Chat -->\s*<div class="bento-card.*?</div>\s*</div>\s*</div>'
    # Wait, the closing tags might be tricky, let's just make the Incident list span the entire column
    if "Aegis AI Copilot" in txt and "bento-card p-5 h-[300px]" in txt:
        # We can just hide it or replace it. Let's replace the whole Incidents & flex col block
        # Actually it's easier to use a regex to strip the chat card.
        txt = re.sub(r'<!-- Quick Actions / AI Chat -->\s*<div class="bento-card.*?<i data-lucide="send".*?</div>\s*</div>', '', txt, flags=re.DOTALL)
    
    write_file(name, txt)

if __name__ == "__main__":
    fix_profile_pages()
    update_dashboard()
    print("UI Polish Completed!")
