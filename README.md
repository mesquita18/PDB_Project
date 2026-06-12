# PDB_Project

Projeto Django contendo o app `rest_api` com a lógica de gerenciamento de alunos, turmas e notas.

## Requisitos
- Python 3.10+ (testado com 3.12)
- virtualenv (módulo `venv` do Python)
- dependências listadas em `requirements.txt` (se não existir, instale `Django==4.2` e `djangorestframework`).

## Como rodar localmente

1. Crie e ative um ambiente virtual:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Instale dependências:

```bash
pip install -r requirements.txt
# se não houver requirements.txt:
pip install Django==4.2 djangorestframework
```

3. Aplique migrações e crie um superuser (opcional):

```bash
.venv/bin/python manage.py migrate
.venv/bin/python manage.py createsuperuser
```

4. Rode o servidor de desenvolvimento:

```bash
.venv/bin/python manage.py runserver
```

5. Acesse http://127.0.0.1:8000/ — a aplicação possui páginas em `/usuarios/...`.

## Notas
- O código principal está em `rest_api/` — o restante do projeto foi reduzido para manter apenas o app funcional.
- O `.gitignore` já exclui o ambiente virtual e o arquivo de banco `db.sqlite3`.
📚 Sistema para Controle Escolar

📖 Descrição
O Sistema para Controle Escolar tem como objetivo gerenciar um banco de dados
de alunos de uma instituição, permitindo o cadastro, visualização e edição de
alunos, turmas e notas. O acesso ao sistema é restrito a usuários autenticados.

🛠 Tecnologias Usadas
    Django (Framework web em Python)
    HTML e CSS (Para o front-end)

🚀 Funcionalidades
✅ Autenticação de Usuário (Login e Logout)
✅ Cadastro e Gerenciamento de Usuários
✅ Cadastro e Gerenciamento de Alunos
✅ Cadastro e Gerenciamento de Disciplinas e Turmas
✅ Lançamento e Edição de Notas dos Alunos
✅ Consulta de Histórico do Aluno
✅ Visualização de Usuários, Alunos, Disciplinas e Turmas
✅ Sistema de Busca para Usuários, Alunos, Disciplinas e Turmas


---

## Limpeza do workspace (adicionado)

Este repositório foi parcialmente organizado para manter o app `rest_api` como o foco principal.

- Criei o script `scripts/cleanup_archive.ps1` que move pastas antigas para `archive/` sem remover arquivos imediatamente.
- Adicionei um `requirements.txt` mínimo com dependências comuns.

Para rodar o script (PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\cleanup_archive.ps1
```

Revise `archive/` após a execução e confirme que tudo está correto antes de apagar permanentemente.

Se quiser, eu executo o script e concluo a organização movendo `Projeto` e `PBD_Projeto` para `archive/` agora.
