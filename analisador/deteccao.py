"""Leitura de logs (acesso HTTP no formato combined e auth.log do SSH) e regras de detecção."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from urllib.parse import unquote_plus

# 203.0.113.9 - - [25/Nov/2026:10:00:01 -0300] "GET /login HTTP/1.1" 200 512 "-" "curl/8.0"
RE_HTTP = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<data>[^\]]+)\] "(?P<metodo>[A-Z]+) (?P<caminho>\S+)[^"]*" '
    r'(?P<status>\d{3}) \S+(?: "[^"]*" "(?P<agente>[^"]*)")?'
)
# Nov 25 10:00:01 servidor sshd[123]: Failed password for root from 198.51.100.7 port 4242 ssh2
RE_SSH_FALHA = re.compile(r"sshd\[\d+\]: Failed password for (?:invalid user )?(?P<usuario>\S+) from (?P<ip>\S+)")
RE_SSH_OK = re.compile(r"sshd\[\d+\]: Accepted \S+ for (?P<usuario>\S+) from (?P<ip>\S+)")

ASSINATURAS = {
    "SQL injection": re.compile(r"(\bunion\b.+\bselect\b|'\s*or\s*'?\d+'?\s*=\s*'?\d|;\s*drop\s+table|sleep\(\d+\)|information_schema)", re.I),
    "XSS": re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=)", re.I),
    "Path traversal": re.compile(r"(\.\./|\.\.\\|/etc/passwd|win\.ini)", re.I),
    "Arquivo sensível": re.compile(r"(/\.env\b|/\.git/|wp-config\.php|/phpmyadmin|/\.aws/)", re.I),
}
AGENTES_SUSPEITOS = re.compile(r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|zgrab)", re.I)


@dataclass
class Alerta:
    tipo: str
    ip: str
    detalhe: str
    severidade: str  # baixa | média | alta

    def como_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class Relatorio:
    linhas_lidas: int = 0
    linhas_ignoradas: int = 0
    requisicoes: int = 0
    status: Counter = field(default_factory=Counter)
    ips: Counter = field(default_factory=Counter)
    caminhos: Counter = field(default_factory=Counter)
    ssh_falhas: Counter = field(default_factory=Counter)
    ssh_sucessos: list = field(default_factory=list)
    alertas: list = field(default_factory=list)

    def resumo(self) -> dict:
        """Dados agregados, sem linhas cruas: é isso que pode ir para a IA."""
        sev = Counter(a.severidade for a in self.alertas)
        return {
            "linhas_lidas": self.linhas_lidas,
            "requisicoes_http": self.requisicoes,
            "status_http": dict(self.status.most_common()),
            "top_ips": self.ips.most_common(5),
            "top_caminhos": self.caminhos.most_common(5),
            "ssh_falhas_por_ip": self.ssh_falhas.most_common(5),
            "alertas_por_severidade": dict(sev),
            "alertas": [a.como_dict() for a in self.alertas[:30]],
        }


def analisar_linhas(linhas, *, limite_ssh: int = 5, limite_404: int = 10) -> Relatorio:
    r = Relatorio()
    erros_404: Counter = Counter()
    ataques_vistos: set = set()
    agentes_vistos: set = set()
    ssh_usuarios: dict = defaultdict(set)

    for bruta in linhas:
        linha = bruta.rstrip("\n")
        if not linha.strip():
            continue
        r.linhas_lidas += 1

        if m := RE_HTTP.match(linha):
            ip, caminho, status = m["ip"], m["caminho"], int(m["status"])
            r.requisicoes += 1
            r.status[status] += 1
            r.ips[ip] += 1
            r.caminhos[caminho.split("?")[0]] += 1
            if status == 404:
                erros_404[ip] += 1
            decodificado = unquote_plus(caminho)
            for nome, regra in ASSINATURAS.items():
                if regra.search(decodificado) and (ip, nome) not in ataques_vistos:
                    ataques_vistos.add((ip, nome))
                    sev = "média" if nome == "Arquivo sensível" else "alta"
                    r.alertas.append(Alerta(nome, ip, f"{m['metodo']} {caminho[:120]}", sev))
            agente = m["agente"] or ""
            if AGENTES_SUSPEITOS.search(agente) and ip not in agentes_vistos:
                agentes_vistos.add(ip)
                r.alertas.append(Alerta("Ferramenta de ataque", ip, f"User-Agent: {agente[:80]}", "média"))
        elif m := RE_SSH_FALHA.search(linha):
            r.ssh_falhas[m["ip"]] += 1
            ssh_usuarios[m["ip"]].add(m["usuario"])
        elif m := RE_SSH_OK.search(linha):
            r.ssh_sucessos.append((m["usuario"], m["ip"]))
        else:
            r.linhas_ignoradas += 1

    for ip, total in r.ssh_falhas.items():
        if total >= limite_ssh:
            usuarios = ", ".join(sorted(ssh_usuarios[ip]))[:80]
            r.alertas.append(Alerta("Força bruta SSH", ip, f"{total} falhas (usuários: {usuarios})", "alta"))
    for usuario, ip in r.ssh_sucessos:
        if r.ssh_falhas.get(ip, 0) >= limite_ssh:
            r.alertas.append(Alerta("Login após força bruta", ip, f"acesso aceito para '{usuario}'", "alta"))
    for ip, total in erros_404.items():
        if total >= limite_404:
            r.alertas.append(Alerta("Varredura de diretórios", ip, f"{total} respostas 404", "média"))

    ordem = {"alta": 0, "média": 1, "baixa": 2}
    r.alertas.sort(key=lambda a: (ordem[a.severidade], a.tipo, a.ip))
    return r
