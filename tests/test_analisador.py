import json

from analisador import analisar_linhas
from analisador.__main__ import main
from analisador.ia import resumo_ia


def tipos(rel):
    return {(a.tipo, a.ip) for a in rel.alertas}


def ler(*arquivos):
    for a in arquivos:
        yield from open(a, encoding="utf-8")


def test_detecta_ataques_no_exemplo():
    rel = analisar_linhas(ler("exemplos/access.log", "exemplos/auth.log"))
    t = tipos(rel)
    assert ("SQL injection", "198.51.100.23") in t
    assert ("XSS", "198.51.100.40") in t
    assert ("Path traversal", "198.51.100.41") in t
    assert ("Varredura de diretórios", "203.0.113.66") in t
    assert ("Ferramenta de ataque", "203.0.113.66") in t
    assert ("Força bruta SSH", "203.0.113.99") in t
    assert ("Login após força bruta", "203.0.113.99") in t


def test_trafego_normal_nao_gera_alerta():
    linhas = [
        '192.0.2.1 - - [25/Nov/2026:10:00:00 -0300] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"',
        "Nov 25 08:00:00 srv sshd[1]: Failed password for joao from 192.0.2.5 port 1 ssh2",
    ]
    rel = analisar_linhas(linhas)
    assert rel.alertas == [] and rel.requisicoes == 1


def test_resumo_sem_chave_usa_regras_locais(monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    rel = analisar_linhas(ler("exemplos/auth.log"))
    texto, origem = resumo_ia(rel.resumo())
    assert origem == "local" and "fail2ban" in texto


def test_falha_na_ia_cai_para_local(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "chave-de-teste")
    monkeypatch.setenv("LLM_BASE_URL", "http://127.0.0.1:9")
    rel = analisar_linhas(ler("exemplos/auth.log"))
    _, origem = resumo_ia(rel.resumo(), timeout=2)
    assert origem == "local"


def test_cli_json(capsys):
    codigo = main(["exemplos/access.log", "--json"])
    dados = json.loads(capsys.readouterr().out)
    assert codigo == 1 and dados["requisicoes_http"] > 0
