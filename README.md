<div align="center">

<img width="100%" src="https://capsule-render.vercel.app/api?type=waving&height=200&color=0:050505,50:6d28d9,100:a855f7&text=ANALISADOR%20DE%20LOGS&fontSize=50&fontColor=ffffff&animation=fadeIn&fontAlignY=35"/>

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=20&duration=2500&pause=800&color=C084FC&center=true&vCenter=true&width=700&lines=FOR%C3%87A+BRUTA%3F+DETECTADO.;SQL+INJECTION%3F+DETECTADO.;RESUMO+POR+IA+COM+FALLBACK"/>

<img src="https://img.shields.io/badge/Python-3.10+-8A2BE2?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/depend%C3%AAncias-zero-6d28d9?style=for-the-badge"/>
<img src="https://img.shields.io/badge/IA-opcional-a855f7?style=for-the-badge"/>

</div>

---

## 🕵️ Sobre

Ferramenta de linha de comando que lê **logs de acesso HTTP** (formato *combined* do Apache/Nginx) e o **auth.log do SSH**, encontra comportamentos suspeitos e escreve uma conclusão com ações recomendadas.

A conclusão pode vir de uma **IA** (qualquer API compatível com a da OpenAI) ou, sem chave ou se a IA falhar, de **regras locais**. Só o resumo agregado vai para a IA, **nunca as linhas cruas do log**.

```bash
╭──────────────────────────────╮
│    ANALISADOR DE LOGS v1.0   │
╰──────────────────────────────╯
Linhas lidas: 77 | Requisições HTTP: 66 | Falhas SSH: 9

[ALTA ] Força bruta SSH          203.0.113.99     8 falhas (usuários: admin, oracle, root, test, ubuntu)
[ALTA ] Login após força bruta   203.0.113.99     acesso aceito para 'admin'
[ALTA ] Path traversal           198.51.100.41    GET /download?arquivo=../../../../etc/passwd
[ALTA ] SQL injection            198.51.100.23    GET /produtos?id=1%27%20OR%20%271%27%3D%271
[ALTA ] XSS                      198.51.100.40    GET /busca?q=%3Cscript%3Ealert(1)%3C/script%3E
[MÉDIA] Varredura de diretórios  203.0.113.66     12 respostas 404
```

## 🔎 O que ele detecta

| Regra | Como |
|---|---|
| 🔐 Força bruta SSH | IPs com 5+ senhas erradas (ajustável com `--limite-ssh`) |
| 🚨 Login após força bruta | Acesso aceito vindo de um IP que estava atacando |
| 💉 SQL injection | `UNION SELECT`, `' OR '1'='1`, `sleep()`, `information_schema`... |
| 🧨 XSS | `<script`, `javascript:`, `onerror=` |
| 📂 Path traversal | `../`, `/etc/passwd`, `win.ini` |
| 🗝️ Arquivo sensível | `/.env`, `/.git/`, `wp-config.php`, `/phpmyadmin` |
| 🗺️ Varredura de diretórios | IPs com 10+ respostas 404 (`--limite-404`) |
| 🛠️ Ferramenta de ataque | User-Agent de sqlmap, nikto, nmap, gobuster... |

## ⚡ Como usar

Não precisa instalar nada além do Python 3.10+.

```bash
python -m analisador exemplos/access.log exemplos/auth.log        # relatório colorido
python -m analisador exemplos/access.log --json                   # saída em JSON
python -m analisador /var/log/auth.log --limite-ssh 3              # regra mais rígida
```

Resumo por IA (opcional):

```bash
export LLM_API_KEY="sua-chave"               # nunca coloque a chave no código
export LLM_BASE_URL="https://api.openai.com/v1"   # ou outro provedor compatível
export LLM_MODEL="gpt-4o-mini"
python -m analisador exemplos/*.log --ia
```

O código de saída é `1` quando há alertas, então dá para usar em scripts e pipelines.

## 🧪 Testes

```bash
pip install pytest
python -m pytest -q
```

Os logs em `exemplos/` são fictícios e usam IPs reservados para documentação (RFC 5737).

---

<div align="center">

Feito com por **[Johnny Lucas](https://github.com/Johnn5527)**

</div>

<img width="100%" src="https://capsule-render.vercel.app/api?type=waving&height=120&section=footer&color=0:050505,50:6d28d9,100:a855f7"/>
