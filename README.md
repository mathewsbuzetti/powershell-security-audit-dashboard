# 🔒 Security Audit Dashboard

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Mathews_Buzetti-blue)](https://www.linkedin.com/in/mathewsbuzetti)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=flat-square&logo=powershell&logoColor=white)
![Status](https://img.shields.io/badge/Status-Production-green?style=flat-square)
![Documentation](https://img.shields.io/badge/Documentation-Technical-blue?style=flat-square)
![Version](https://img.shields.io/badge/Version-1.1-orange?style=flat-square)

**Aplica-se a:** ✔️ Windows Server ✔️ Compartilhamentos de Rede ✔️ Permissões NTFS

## 📋 Descrição

Uma ferramenta PowerShell avançada para análise de permissões de segurança em compartilhamentos de rede Windows. Gera um dashboard HTML interativo e moderno que permite identificar e corrigir problemas como:

- Permissões atribuídas diretamente a usuários
- Grupos com permissões excessivas ou desnecessárias
- Quebras de herança de permissões
- Análise de conformidade AGDLP

O dashboard interativo facilita a análise de permissões, oferecendo recursos de filtragem, busca e visualização gráfica dos problemas encontrados.

## ✨ Recursos Principais

- 🚀 **Escaneamento Eficiente**: Análise recursiva de permissões em compartilhamentos de rede
- 📊 **Dashboard Interativo**: Visualização moderna com gráficos e métricas
- 🧰 **Detecção de Problemas**: Identificação automática de configurações inseguras
- 🔍 **Filtragem Avançada**: Interface de busca e filtragem para análise detalhada
- 📈 **Métricas de Risco**: Cálculo de índice de risco baseado em problemas detectados
- 🔄 **Processamento em Lotes**: Gerenciamento eficiente de memória para grandes ambientes

## 📋 Índice

1. [Requisitos](#-requisitos)
2. [Instalação](#-instalação)
3. [Como Usar](#-como-usar)
4. [Parâmetros](#-parâmetros)
5. [Interface do Dashboard](#-interface-do-dashboard)
6. [Recomendações de Segurança](#-recomendações-de-segurança)
7. [Problemas Conhecidos](#-problemas-conhecidos)
8. [Suporte](#-suporte)
9. [Licença](#-licença)
10. [Créditos](#-créditos)

## 💻 Requisitos

- Windows PowerShell 5.1 ou superior
- Permissões de administrador para ler ACLs nos compartilhamentos
- Acesso aos compartilhamentos de rede a serem analisados
- Navegador moderno para visualização do dashboard HTML

## 🚀 Instalação

1. Clone este repositório:
   ```powershell
   git clone https://github.com/mathewsbuzetti/powershell-security-audit-dashboard.git
   ```

2. Entre na pasta do projeto:
   ```powershell
   cd powershell-security-audit-dashboard
   ```

3. Se necessário, desbloqueie o script:
   ```powershell
   Unblock-File -Path .\SecurityAuditDashboard.ps1
   ```

## 🚀 Como Usar

1. Execute o script com os parâmetros desejados:

   ```powershell
   .\SecurityAuditDashboard.ps1 -ServerIP "192.168.1.250" -NetworkShares "\\192.168.1.250\dados\Tree" -OutputPath "C:\temp\SecurityAudit" -MaxDepth 3
   ```

2. Aguarde o escaneamento ser concluído. O progresso será exibido no terminal.

3. Abra o dashboard HTML gerado no navegador. Por padrão, será aberto automaticamente ao final do processo.

### Exemplo de Uso Completo

```powershell
.\SecurityAuditDashboard.ps1 -ServerIP "192.168.1.250" `
                          -NetworkShares @("\\192.168.1.250\dados\Tree", "\\192.168.1.250\dados\Public") `
                          -OutputPath "C:\temp\SecurityAudit" `
                          -MaxDepth 4 `
                          -BatchSize 1500 `
                          -MaxConcurrentJobs 3 `
                          -SkipFolders @("$", "System Volume Information", "Recycle.Bin", "Temp") `
                          -GenerateHTML
```

## 🔧 Parâmetros

| Parâmetro | Tipo | Descrição | Padrão |
|-----------|------|-----------|--------|
| ServerIP | string | Endereço IP do servidor que será analisado | "192.168.1.250" |
| NetworkShares | array | Lista de compartilhamentos a serem analisados | @("\\\\$ServerIP\dados\Tree") |
| OutputPath | string | Pasta de destino para arquivos de saída | "C:\temp\SecurityAudit" |
| MaxDepth | int | Profundidade máxima de recursão em subpastas | 3 |
| BatchSize | int | Número de pastas processadas por lote | 1000 |
| MaxConcurrentJobs | int | Número máximo de jobs concorrentes | 5 |
| SkipFolders | array | Pastas a serem ignoradas na análise | @("$", "System Volume Information", "Recycle.Bin") |
| GenerateHTML | switch | Gerar dashboard HTML interativo | $true |

## 📊 Interface do Dashboard

O dashboard HTML gerado fornece uma visualização interativa dos dados de permissões:

### 1. Resumo de Métricas

- Total de pastas analisadas
- Total de permissões encontradas
- Problemas de segurança detectados
- Índice de risco calculado

### 2. Visualizações Gráficas

- Distribuição de problemas por tipo
- Top 5 usuários/grupos com mais permissões
- Análise de severidade (Alta, Média, Baixa)
- Conformidade com modelo AGDLP

### 3. Tabela de Problemas

Interface completa com recursos de:
- Busca em tempo real
- Filtragem por severidade, tipo, pasta e entidade
- Paginação de resultados
- Exportação de dados

## 🛡️ Recomendações de Segurança

Para melhorar a segurança de suas permissões, considere as seguintes recomendações:

1. **Elimine permissões diretas de usuários**
   - Substitua por grupos de segurança para facilitar a administração

2. **Reduza permissões de "Controle Total"**
   - Aplique o princípio do menor privilégio
   - Conceda apenas as permissões necessárias

3. **Simplifique heranças quebradas**
   - Reative a herança quando possível
   - Documente quando a quebra for necessária

4. **Implemente o modelo AGDLP**
   - Account → Global Group → Domain Local Group → Permission
   - Facilita a gestão e auditoria

## ⚠️ Problemas Conhecidos

- O escaneamento de permissões pode ser lento em estruturas de pastas muito grandes
- Alguns caracteres especiais em nomes de pastas podem causar problemas
- Em ambientes com muitas ACLs, o consumo de memória pode ser elevado

## 👏 Créditos

Desenvolvido por Mathews Buzetti.
