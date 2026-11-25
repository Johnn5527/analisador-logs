"""Resumo em linguagem natural: usa uma IA compatível com a API da OpenAI se houver chave, senão regras locais.

Somente o resumo agregado (contagens e alertas) é enviado, nunca as linhas cruas do log.
Variáveis de ambiente (opcionais): LLM_API_KEY, LLM_BASE_URL, LLM_MODEL.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

PROMPT = (
    "Você é um analista de segurança. Com base no resumo JSON de um log, escreva em português, "
    "em até 6 tópicos curtos, o que aconteceu, o risco e as ações recomendadas."
)


def resumo_local(resumo: dict) -> str:
    alertas = resumo["alertas"]
    if not alertas:
        return "✔ Nenhum comportamento suspeito encontrado nas regras atuais."
    linhas = [f"⚠ {len(alertas)} alerta(s) encontrado(s):"]
    tipos = {}
    for a in alertas:
        tipos.setdefault(a["tipo"], set()).add(a["ip"])
    for tipo, ips in tipos.items():
        linhas.append(f"- {tipo}: {len(ips)} IP(s) ({', '.join(sorted(ips)[:3])})")
    recomendacoes = {
        "Força bruta SSH": "bloquear os IPs (fail2ban) e desativar login por senha no SSH",
        "Login após força bruta": "verificar a conta comprometida imediatamente e trocar as credenciais",
        "SQL injection": "revisar consultas e usar parâmetros preparados",
        "XSS": "escapar a saída e aplicar Content-Security-Policy",
        "Path traversal": "validar caminhos e nunca montar arquivos com entrada do usuário",
        "Arquivo sensível": "garantir que .env e .git não sejam servidos",
        "Varredura de diretórios": "limitar requisições por IP (rate limit) ou usar WAF",
        "Ferramenta de ataque": "bloquear o User-Agent e monitorar o IP",
    }
    linhas.append("Ações recomendadas:")
    linhas += [f"- {recomendacoes[t]}" for t in tipos if t in recomendacoes]
    return "\n".join(linhas)


def resumo_ia(resumo: dict, timeout: float = 20) -> tuple[str, str]:
    """Retorna (texto, origem). origem é 'ia' ou 'local'."""
    chave = os.getenv("LLM_API_KEY")
    if not chave:
        return resumo_local(resumo), "local"
    base = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    corpo = json.dumps({
        "model": os.getenv("LLM_MODEL", "gpt-4o-mini"),
        "messages": [
            {"role": "system", "content": PROMPT},
            {"role": "user", "content": json.dumps(resumo, ensure_ascii=False)},
        ],
        "temperature": 0.2,
    }).encode()
    req = urllib.request.Request(
        f"{base}/chat/completions",
        data=corpo,
        headers={"Authorization": f"Bearer {chave}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            dados = json.load(resp)
        return dados["choices"][0]["message"]["content"].strip(), "ia"
    except (urllib.error.URLError, TimeoutError, KeyError, IndexError, ValueError):
        return resumo_local(resumo), "local"
