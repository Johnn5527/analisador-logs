"""Uso: python -m analisador exemplos/access.log exemplos/auth.log [--json] [--ia]"""

import argparse
import json
import sys

from .deteccao import analisar_linhas
from .ia import resumo_ia, resumo_local

CORES = {"alta": "\033[91m", "média": "\033[93m", "baixa": "\033[96m"}
ROXO, FIM = "\033[95m", "\033[0m"


def ler(caminhos):
    for caminho in caminhos:
        with open(caminho, encoding="utf-8", errors="replace") as f:
            yield from f


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="analisador", description="Analisador de logs 🕵️")
    p.add_argument("arquivos", nargs="+")
    p.add_argument("--json", action="store_true", help="saída em JSON")
    p.add_argument("--ia", action="store_true", help="resumo por IA (usa LLM_API_KEY; sem ela, cai para regras locais)")
    p.add_argument("--limite-ssh", type=int, default=5)
    p.add_argument("--limite-404", type=int, default=10)
    a = p.parse_args(argv)

    rel = analisar_linhas(ler(a.arquivos), limite_ssh=a.limite_ssh, limite_404=a.limite_404)
    resumo = rel.resumo()
    texto, origem = resumo_ia(resumo) if a.ia else (resumo_local(resumo), "local")

    if a.json:
        print(json.dumps({**resumo, "conclusao": texto, "origem_conclusao": origem}, ensure_ascii=False, indent=2))
        return 1 if rel.alertas else 0

    cor = sys.stdout.isatty()
    c = (lambda k: CORES.get(k, "")) if cor else (lambda k: "")
    roxo, fim = (ROXO, FIM) if cor else ("", "")
    print(f"{roxo}╭──────────────────────────────╮\n│    ANALISADOR DE LOGS v1.0   │\n╰──────────────────────────────╯{fim}")
    print(f"Linhas lidas: {rel.linhas_lidas} | Requisições HTTP: {rel.requisicoes} | Falhas SSH: {sum(rel.ssh_falhas.values())}")
    if rel.ips:
        print("Top IPs: " + ", ".join(f"{ip} ({n})" for ip, n in rel.ips.most_common(3)))
    print()
    for al in rel.alertas:
        print(f"{c(al.severidade)}[{al.severidade.upper():5}]{fim} {al.tipo:24} {al.ip:16} {al.detalhe}")
    print(f"\n{roxo}Conclusão ({'IA' if origem == 'ia' else 'regras locais'}):{fim}\n{texto}")
    return 1 if rel.alertas else 0


if __name__ == "__main__":
    sys.exit(main())
