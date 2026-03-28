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

def fix_inputs():
    for name in ["profile.html", "admin_user_profile.html", "mfa_setup.html"]:
        txt = read_file(name)
        if not txt: continue
        # Replace white inputs with the existing dark fluent inputs
        txt = txt.replace('class="input-field"', 'class="fluent-input"')
        txt = txt.replace('class="input-field opacity-50"', 'class="fluent-input opacity-50"')
        write_file(name, txt)

def update_dashboard():
    name = "dashboard.html"
    txt = read_file(name)
    if not txt: return
    
    # 1. Remove "Aegis Copilot" from sidebar
    # Look for the nav-copilot block: <a href="#" onclick="switchView('copilot')" id="nav-copilot" ...>...</a>
    txt = re.sub(r'<a href="#" onclick="switchView\(\'copilot\'\)" id="nav-copilot".*?</a>', '', txt, flags=re.DOTALL)
    
    # 2. Add Animations CSS
    anim_css = """
    /* Animations & Floating Chat */
    @keyframes rotateBg { 100% { transform: rotate(360deg); } }
    @keyframes pulseSoft { 0%, 100% { transform: scale(1); opacity: 1; } 50% { transform: scale(1.05); opacity: 0.7; } }
    
    .bg-animated {
        position: fixed; top: -50%; left: -50%; width: 200%; height: 200%;
        background-image: radial-gradient(circle at 50% 50%, rgba(14, 165, 233, 0.05) 0%, transparent 40%),
                          radial-gradient(circle at 20% 80%, rgba(139, 92, 246, 0.05) 0%, transparent 40%);
        animation: rotateBg 60s linear infinite;
        z-index: 0; pointer-events: none;
    }
    
    .nav-item-animated:hover i, .side-icon:hover { animation: pulseSoft 1s infinite; }
    
    #floating-chat-bubble {
        position: fixed; bottom: 30px; right: 30px; z-index: 999;
        width: 60px; height: 60px; border-radius: 50%;
        background: linear-gradient(135deg, #a855f7, #6366f1);
        box-shadow: 0 10px 30px rgba(99, 102, 241, 0.4);
        cursor: pointer; display: flex; align-items: center; justify-content: center;
        transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275); color: white;
        font-size: 24px;
    }
    #floating-chat-bubble:hover { transform: scale(1.1) translateY(-5px); box-shadow: 0 15px 40px rgba(99, 102, 241, 0.6); }
    
    #view-copilot {
        position: fixed !important; bottom: 100px !important; right: 30px !important; z-index: 998 !important;
        width: 380px !important; height: 500px !important; border-radius: 20px !important;
        background: rgba(20, 20, 20, 0.95) !important; backdrop-filter: blur(20px) !important;
        box-shadow: 0 20px 50px rgba(0,0,0,0.5) !important;
        transform: translateY(20px) scale(0.9) !important; opacity: 0 !important; pointer-events: none !important;
        transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275) !important;
        display: flex !important; flex-direction: column !important; margin: 0 !important;
    }
    #view-copilot.open { transform: translateY(0) scale(1) !important; opacity: 1 !important; pointer-events: auto !important; }
"""
    if "/* Animations & Floating Chat */" not in txt:
        txt = txt.replace("</style>", anim_css + "\n</style>")
        txt = txt.replace("<body>", "<body>\n  <div class=\"bg-animated\"></div>")

    # 3. Add Bubble Button
    bubble_html = """
  <div id="floating-chat-bubble" onclick="toggleChat()">
      ✨
  </div>
"""
    if "id=\"floating-chat-bubble\"" not in txt:
        txt = txt.replace("</body>", bubble_html + "\n</body>")

    # 4. Remove 'hidden' from view-copilot so it's controlled by float CSS
    txt = txt.replace('id="view-copilot" class="main-view hidden h-full', 'id="view-copilot" class="main-view h-full')
    
    # 5. Add toggle logic
    js_logic = """
    let chatOpen = false;
    function toggleChat() {
        chatOpen = !chatOpen;
        const w = document.getElementById('view-copilot');
        const b = document.getElementById('floating-chat-bubble');
        if(chatOpen) { w.classList.add('open'); b.innerText = '❌'; }
        else { w.classList.remove('open'); b.innerText = '✨'; }
    }
    """
    if "function toggleChat" not in txt:
        txt = txt.replace("</script>\n</body>", js_logic + "\n</script>\n</body>")
        txt = txt.replace("</script>\r\n</body>", js_logic + "\n</script>\n</body>")
        
        # If it couldn't find </script></body>, just toss it before </body>
        if "function toggleChat" not in txt:
            txt = txt.replace("</body>", "<script>\n" + js_logic + "\n</script>\n</body>")

    write_file(name, txt)

if __name__ == "__main__":
    fix_inputs()
    update_dashboard()
    print("Intune UI fixed!")
