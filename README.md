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
