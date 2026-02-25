import customtkinter as ctk
import threading
import time
import logging
from ..core.agent import AegisAgentCore
from ..core.commands import handle_command

log = logging.getLogger("aegis-agent")
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class AegisAgentGUI(ctk.CTk):
    def __init__(self, agent: AegisAgentCore):
        super().__init__()
        self.agent = agent
        self.agent.on_log_callback = self.append_log
        self.agent.on_chat_callback = self.refresh_chat

        self.title("Aegis EDR - Endpoint Agent")
        self.geometry("800x600")
        self.protocol("WM_DELETE_WINDOW", self.hide_window)

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)

        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(5, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="🛡️ AEGIS", font=ctk.CTkFont(size=24, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.status_label = ctk.CTkLabel(self.sidebar_frame, text="Status: Aguardando...", text_color="yellow")
        self.status_label.grid(row=1, column=0, padx=20, pady=10)

        self.btn_logs = ctk.CTkButton(self.sidebar_frame, text="Logs do Sistema", command=self.show_logs)
        self.btn_logs.grid(row=2, column=0, padx=20, pady=10)

        self.btn_chat = ctk.CTkButton(self.sidebar_frame, text="Suporte SOC", command=self.show_chat)
        self.btn_chat.grid(row=3, column=0, padx=20, pady=10)

        self.btn_req = ctk.CTkButton(self.sidebar_frame, text="Solicitar Chat", fg_color="#b91c1c", hover_color="#991b1b", command=self.agent.request_chat_support)
        self.btn_req.grid(row=4, column=0, padx=20, pady=10)

        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        self.logs_view = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.logs_view.grid(row=0, column=0, sticky="nsew")
        self.logs_view.grid_rowconfigure(1, weight=1)
        self.logs_view.grid_columnconfigure(0, weight=1)

        lbl1 = ctk.CTkLabel(self.logs_view, text="Eventos do Agente", font=ctk.CTkFont(size=18, weight="bold"))
        lbl1.grid(row=0, column=0, sticky="w", pady=(0, 10))
        self.log_box = ctk.CTkTextbox(self.logs_view, state="disabled")
        self.log_box.grid(row=1, column=0, sticky="nsew")

        self.chat_view = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.chat_view.grid_rowconfigure(1, weight=1)
        self.chat_view.grid_columnconfigure(0, weight=1)

        lbl2 = ctk.CTkLabel(self.chat_view, text="Chat Seguro com SOC", font=ctk.CTkFont(size=18, weight="bold"))
        lbl2.grid(row=0, column=0, sticky="w", pady=(0, 10))
        self.chat_box = ctk.CTkTextbox(self.chat_view, state="disabled")
        self.chat_box.grid(row=1, column=0, sticky="nsew", pady=(0, 10))

        self.chat_input_frame = ctk.CTkFrame(self.chat_view, fg_color="transparent")
        self.chat_input_frame.grid(row=2, column=0, sticky="ew")
        self.chat_input_frame.grid_columnconfigure(0, weight=1)
        self.chat_entry = ctk.CTkEntry(self.chat_input_frame, placeholder_text="Digite sua mensagem...")
        self.chat_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.chat_entry.bind("<Return>", lambda e: self.send_chat_msg())
        btn_send = ctk.CTkButton(self.chat_input_frame, text="Enviar", width=80, command=self.send_chat_msg)
        btn_send.grid(row=0, column=1)

        self.show_logs()
        self.append_log("Interface gráfica iniciada.")

        threading.Thread(target=self.agent_loop, daemon=True).start()
        threading.Thread(target=self.vuln_loop, daemon=True).start()
        threading.Thread(target=self.fim_loop, daemon=True).start()

    def hide_window(self):
        self.iconify()

    def show_logs(self):
        self.chat_view.grid_forget()
        self.logs_view.grid(row=0, column=0, sticky="nsew")

    def show_chat(self):
        self.logs_view.grid_forget()
        self.chat_view.grid(row=0, column=0, sticky="nsew")
        self.refresh_chat()

    def append_log(self, msg: str):
        t = time.strftime("%H:%M:%S")
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"[{t}] {msg}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def refresh_chat(self):
        self.chat_box.configure(state="normal")
        self.chat_box.delete("1.0", "end")
        for m in self.agent.chat_history:
            sender = "💻 SOC Admin" if m["sender"] == "admin" else "👤 Você"
            self.chat_box.insert("end", f"{sender} ({m['time'][11:16]}):\n{m['message']}\n\n")
        self.chat_box.see("end")
        self.chat_box.configure(state="disabled")

    def send_chat_msg(self):
        msg = self.chat_entry.get().strip()
        if not msg: return
        self.chat_entry.delete(0, "end")
        mt = time.strftime("%Y-%m-%dT%H:%M:%S")
        self.agent.chat_history.append({"sender": "agent", "message": msg, "time": mt})
        self.refresh_chat()
        threading.Thread(target=self.agent.poll_chat, args=(msg,), daemon=True).start()

    def set_status(self, is_online):
        color = "#00ff00" if is_online else "red"
        text = "Status: ONLINE" if is_online else "Status: OFFLINE"
        self.status_label.configure(text=text, text_color=color)

    def agent_loop(self):
        time.sleep(2)
        while True:
            resp = self.agent.heartbeat()
            self.set_status(resp is not None)
            if resp and resp.get("pending_command"):
                handle_command(self.agent, resp["pending_command"])
            self.agent.flush_events()
            self.agent.poll_chat()
            time.sleep(15)

    def vuln_loop(self):
        time.sleep(10)
        while True:
            self.agent.run_vuln_scan()
            time.sleep(300)

    def fim_loop(self):
        time.sleep(5)
        while True:
            self.agent.run_fim()
            time.sleep(30)
