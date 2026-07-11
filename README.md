# mini-siem

Um SIEM caseiro (mini-Splunk) que **ingere logs**, **normaliza** em eventos
estruturados, **armazena** em SQLite, permite **consultas** e roda **regras de
correlação/detecção** (brute-force SSH, varredura web).

> ⚠️ Ferramenta educacional/defensiva para logs de sistemas seus.

## Instalação

Pré-requisitos: **Python 3.10+**.

```bash
git clone https://github.com/Diogo-Damasceno/mini-siem.git
cd mini-siem
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

Após instalar, o comando do projeto fica disponível dentro do venv.
Para usar fora dele, crie um atalho:

```bash
mkdir -p ~/.local/bin
ln -sf "$(pwd)/.venv/bin/minisiem" ~/.local/bin/minisiem
```

> Dica: se `~/.local/bin` não estiver no teu `PATH`, rode
> `export PATH="$HOME/.local/bin:$PATH"` (e adicione ao `~/.bashrc`/`~/.zshrc`).


## Uso

```bash
# ingere um log de auth
minisiem ingest /var/log/auth.log --type ssh

# consulta eventos (filtra por IP)
minisiem query --ip 185.220.101.1 --limit 20

# roda deteccoes (brute-force, web scan)
minisiem detect

# estatisticas gerais
minisiem stats
```

## Licença

MIT — veja `LICENSE`.
