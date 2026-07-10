# Mini-SIEM 📊

Um SIEM caseiro (mini-Splunk) que **ingere logs**, **normaliza** em eventos estruturados, **armazena** em SQLite, permite **consultas** e roda **regras de correlação/detecção** (brute-force SSH, varredura web).

> Núcleo funcional (parsers + storage + regras) pronto. Dashboard React/Grafana e backend Go estão no roadmap — ver abaixo.

## Estado atual (funcional ✅)

- Parsers: **sshd** (auth_failure/success/invalid_user), **syslog**, **nginx access**
- Armazenamento e consulta em **SQLite**
- Regras de detecção:
  - `ssh_bruteforce` — N falhas do mesmo IP
  - `web_scan` — muitos 404 do mesmo IP
- CLI de ingestão (arquivo ou stdin), consulta, stats e detecção

## Instalação

```bash
git clone https://github.com/Diogo-Damasceno/mini-siem.git
cd mini-siem
pip install -e .
```

## Uso

```bash
# ingerir o log de exemplo (detecta brute-force + web scan)
minisiem --db siem.db ingest samples/auth.log

# via stdin (ex.: journald)
journalctl -u sshd --no-pager | minisiem ingest

# consultar e estatísticas
minisiem --db siem.db query --type auth_failure
minisiem --db siem.db stats
minisiem --db siem.db detect
```

### Saída de exemplo

```
[*] 18 eventos ingeridos.
  [!] CRITICAL ssh_bruteforce: 6 tentativas de autenticação falhas de 45.9.148.2
  [!] WARNING web_scan: 11 respostas 404 de 185.100.87.1 (possível varredura)
```

## Arquitetura

```
minisiem/
├── parsers.py   # normalização de logs -> Event  [✅ funcional]
├── store.py     # SQLite + regras de detecção      [✅ funcional]
└── cli.py       # ingestão / consulta / detecção    [✅ funcional]
```

## Roadmap (expansão para SIEM completo)

- [ ] Backend HTTP (FastAPI/Go) expondo consultas e alertas
- [ ] Dashboard web (React) com gráficos de eventos/alertas
- [ ] Coletores para Docker, firewall (nftables), auditd
- [ ] Regras adicionais (impossible travel, exfil, privilege escalation)
- [ ] PostgreSQL como backend para alto volume
- [ ] Integração com o Threat Intelligence Platform (enriquecimento de IOCs)

## Testes

```bash
pip install -e '.[dev]'
pytest -q
```

## Licença

MIT
