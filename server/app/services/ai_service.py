import os
from extensions import log


SYSTEM_PROMPT_SOC = """Você é o AEGIS AI, um especialista em cibersegurança integrado ao painel SOC da plataforma Aegis SIEM & EDR.
Responda em português brasileiro. Seja preciso, técnico e objetivo.
Ao analisar eventos, mencione sempre: tipo de ameaça, técnica MITRE ATT&CK, impacto e recomendações de resposta."""


def get_ai_response(message: str, history: list) -> tuple[str, str]:
    response_text = None
    model_used = None

    gemini_key = os.getenv("GEMINI_API_KEY")
    if gemini_key and not response_text:
        try:
            import google.generativeai as genai
            genai.configure(api_key=gemini_key)
            model = genai.GenerativeModel("gemini-1.5-flash", system_instruction=SYSTEM_PROMPT_SOC)
            chat_hist = [
                {"role": ("user" if m.role == "user" else "model"), "parts": [m.content]}
                for m in history[:-1]
            ]
            gchat = model.start_chat(history=chat_hist)
            resp = gchat.send_message(message)
            response_text = resp.text
            model_used = "gemini-1.5-flash"
        except Exception as e:
            log.warning(f"Gemini falhou: {e}")

    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key and not response_text:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=openai_key)
            messages = [{"role": "system", "content": SYSTEM_PROMPT_SOC}]
            for m in history:
                messages.append({"role": m.role, "content": m.content})
            resp = client.chat.completions.create(
                model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                messages=messages,
                max_tokens=1024,
            )
            response_text = resp.choices[0].message.content
            model_used = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        except Exception as e:
            log.warning(f"OpenAI falhou: {e}")

    if not response_text:
        response_text = (
            "⚠️ Nenhuma chave de AI configurada. Configure GEMINI_API_KEY ou OPENAI_API_KEY "
            "no arquivo .env para ativar o assistente de IA."
        )
        model_used = "offline"

    return response_text, model_used
