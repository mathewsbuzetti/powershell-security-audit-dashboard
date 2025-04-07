# 🔒 Security Audit Dashboard - PowerShell

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Mathews_Buzetti-blue)](https://www.linkedin.com/in/mathewsbuzetti)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=flat-square&logo=powershell&logoColor=white)
![Status](https://img.shields.io/badge/Status-Production-green?style=flat-square)
![Documentation](https://img.shields.io/badge/Documentation-Technical-blue?style=flat-square)

**Aplica-se a:** ✔️ Windows Server 2016/2019/2022 ✔️ Compartilhamentos de Rede ✔️ Permissões NTFS

## 📋 Metadados

| Metadado | Descrição |
|----------|-----------|
| **Título** | Security Audit Dashboard - Análise de Permissões NTFS |
| **Versão** | 1.1.0 |
| **Data** | 07/04/2025 |
| **Autor** | Mathews Buzetti |
| **Tags** | `powershell`, `security-audit`, `ntfs-permissions`, `dashboard`, `html-report` |
| **Status** | ✅ Aprovado para ambiente de produção |

## 📷 Visualização do Relatório Interativo

A ferramenta gera um dashboard HTML interativo que facilita a visualização e análise de problemas de permissões em compartilhamentos de rede. O relatório inclui gráficos, estatísticas e uma tabela interativa com recursos de filtragem e busca avançada.

<p align="center">
  <strong>👇 Clique no botão abaixo para visualizar um exemplo de dashboard de análise de segurança 👇</strong>
  <br><br>
  <a href="https://mathewsbuzetti.github.io/powershell-security-audit-dashboard/" target="_blank">
    <img src="https://img.shields.io/badge/Acessar%20Demo-Dashboard:%20Análise%20de%20Segurança-brightgreen?style=for-the-badge&logo=html5" alt="Acessar Demo" width="400">
  </a>
  <br>
  <em>O demo mostra todas as funcionalidades do dashboard, incluindo métricas, gráficos e tabela de análise interativa</em>
</p>

![image](https://github.com/user-attachments/assets/c86feab3-850a-4bd1-95d5-7c64717da385)

![image](https://github.com/user-attachments/assets/913fc712-665b-4780-a0d4-a389958fcdcd)

![image](https://github.com/user-attachments/assets/52363165-ea22-43f2-9a65-5167f21aa8e0)

## 📋 Índice

1. [Metadados](#-metadados)
2. [Visualização do Relatório Interativo](#-visualização-do-relatório-interativo)
3. [Funcionalidades](#-funcionalidades)
4. [Pré-requisitos](#-pré-requisitos)
5. [Como Usar](#-como-usar)
6. [Parâmetros do Script](#-parâmetros-do-script)
7. [Tratamento de Erros e Feedback](#-tratamento-de-erros-e-feedback)
8. [Relatório HTML](#-relatório-html)
9. [Recomendações de Segurança](#-recomendações-de-segurança)
10. [Versionamento](#-versionamento)

## 💻 Funcionalidades

### 📊 Principais Recursos
* Escaneamento automatizado de permissões NTFS em compartilhamentos de rede
* Processamento em lotes para otimização de memória e desempenho
* Detecção inteligente de problemas de segurança e configurações de risco
* Dashboard HTML interativo com gráficos, estatísticas e tabela de análise
* Suporte para múltiplos compartilhamentos em uma única execução
* Cálculo automático de índice de risco de segurança
* Exportação de dados completos para CSV

### 🔍 Detecção de Problemas de Segurança
* Permissões atribuídas diretamente a usuários
* Grupos com permissões excessivas (FullControl)
* Quebras de herança desnecessárias
* Violações de conformidade com modelo AGDLP
* Identificação de contas do sistema com privilégios elevados

### 📈 Dashboard HTML Avançado
* Métricas de resumo com contadores e índice de risco
* Gráficos de distribuição de problemas por tipo e severidade
* Top 5 usuários/grupos com mais permissões
* Tabela completa de problemas com filtros e busca
* Sistema de classificação de severidade (Alta, Média, Baixa)
* Seção de recomendações personalizadas

## 📋 Pré-requisitos

* Windows 10/11 ou Windows Server 2016/2019/2022
* PowerShell 5.1 ou superior
* Permissões de leitura nos compartilhamentos de rede a serem analisados
* Navegador moderno para visualizar o dashboard HTML (Chrome, Edge, Firefox)
* Acesso administrativo para ler permissões NTFS

## 🚀 Como Usar

1. Baixe o script:

[![Download Script SecurityAuditDashboard.ps1](https://img.shields.io/badge/Download%20Script%20SecurityAuditDashboard-blue?style=flat-square&logo=powershell)](https://github.com/mathewsbuzetti/powershell-security-audit-dashboard/blob/main/Script/SecurityAuditDashboard.ps1)

2. Abra o script no PowerShell ISE

3. Localize as linhas abaixo no início do script e altere para o IP do seu servidor e o compartilhamento de rede que deseja analisar:

```powershell
# Configurações que você deve alterar:
[string]$ServerIP = "10.0.0.15"  # Altere para o IP do seu servidor
[array]$NetworkShares = @("\\$ServerIP\compartilhamento")  # Altere para seu compartilhamento
[string]$OutputPath = "C:\temp\SecurityAudit"  # Altere para pasta onde salvará relatórios
```

4. Execute o script pressionando F5 ou o botão de Play no PowerShell ISE

5. Para maior flexibilidade, você também pode executar o script diretamente no PowerShell com parâmetros específicos. Abaixo está um exemplo preenchido com parâmetros comuns:

```powershell
.\SecurityAuditDashboard.ps1 -ServerIP "10.0.0.15" `
                             -NetworkShares @("\\10.0.0.15\compartilhamento\RH", "\\10.0.0.15\compartilhamento\Financeiro") `
                             -OutputPath "C:\temp\SecurityAudit" `
                             -MaxDepth 5 `
                             -BatchSize 2000 `
                             -MaxConcurrentJobs 4 `
                             -SkipFolders @("$", "System Volume Information", "Recycle.Bin", "Backups") `
                             -GenerateHTML
```

> [!WARNING]\
> **Parâmetros avançados e seus impactos:**
> - **MaxDepth**: Define a profundidade máxima de pastas que serão analisadas. Valores mais altos (como 5) analisam mais subpastas, mas aumentam significativamente o tempo de execução.
> - **BatchSize**: Define quantas pastas são processadas em cada lote. Valores maiores (2000) usam mais memória, mas podem ser mais rápidos em sistemas com muita RAM. Reduza para 500-1000 em sistemas com memória limitada.
> - **MaxConcurrentJobs**: Define quantos processamentos paralelos serão executados simultaneamente. Aumentar (4+) pode melhorar a velocidade em CPUs multi-core, mas pode sobrecarregar servidores em produção durante horário comercial.
> - **SkipFolders**: Lista de diretórios que serão ignorados durante a análise. Use este parâmetro para excluir pastas do sistema ou diretórios que não precisam ser verificados, economizando tempo de processamento e evitando erros com pastas especiais. Os valores padrão (`$`, `System Volume Information`, `Recycle.Bin`) são recomendados para qualquer análise.

### Resultados
- O script mostrará o progresso em tempo real no console, com informações detalhadas sobre o processo
- Ao concluir, um dashboard HTML interativo será gerado na pasta de saída configurada
- O dashboard será aberto automaticamente no navegador padrão
- Um arquivo CSV com todos os dados brutos também será gerado para análises adicionais

## 🔧 Parâmetros do Script

| Parâmetro | Tipo | Descrição | Valor Padrão |
|-----------|------|-----------|--------------|
| `ServerIP` | string | Endereço IP do servidor que será analisado | "10.0.0.15" |
| `NetworkShares` | array | Lista de compartilhamentos a serem analisados | @("\\\\$ServerIP\compartilhamento") |
| `OutputPath` | string | Pasta de destino para arquivos de saída | "C:\Relatorios\Seguranca" |
| `MaxDepth` | int | Profundidade máxima de recursão em subpastas | 3 |
| `BatchSize` | int | Número de pastas processadas por lote | 1000 |
| `MaxConcurrentJobs` | int | Número máximo de jobs concorrentes | 5 |
| `SkipFolders` | array | Pastas a serem ignoradas na análise | @("$", "System Volume Information", "Recycle.Bin") |
| `GenerateHTML` | switch | Gerar dashboard HTML interativo | $true |
| `Compact` | bool | Modo compacto para console (menos verbose) | $true |
| `LogLevel` | string | Nível de detalhamento dos logs ("Normal", "Verbose") | "Normal" |

## ⚠️ Tratamento de Erros e Feedback

O script fornece feedback visual em tempo real com cores diferentes:
- 🟦 **Azul/Ciano**: Informações do processo e progresso
- 🟩 **Verde**: Operações concluídas com sucesso
- 🟨 **Amarelo**: Avisos e alertas não críticos
- 🟥 **Vermelho**: Erros que requerem atenção

Erros comuns que são tratados automaticamente:
- Pastas inacessíveis ou com permissões insuficientes
- Arquivos bloqueados ou em uso por outros processos
- Problemas de rede em compartilhamentos remotos
- Limites de memória durante o processamento (gerenciados pelo sistema de lotes)

## 📊 Relatório HTML

O dashboard HTML gerado inclui:

1. **Cabeçalho com Informações Gerais**
   - Servidor e compartilhamentos analisados
   - Data e hora da análise
   - Estatísticas gerais (pastas, permissões, problemas)

2. **Resumo de Métricas**
   - Total de pastas analisadas
   - Total de permissões encontradas
   - Problemas de segurança detectados
   - Índice de risco calculado

3. **Visualizações Gráficas**
   - Distribuição de problemas por tipo
   - Top 5 usuários/grupos com mais permissões
   - Análise de severidade (Alta, Média, Baixa)
   - Conformidade com modelo AGDLP

4. **Seção de Insights e Recomendações**
   - Recomendações específicas com base nos problemas encontrados
   - Priorização por nível de severidade
   - Sugestões de boas práticas

5. **Tabela Detalhada de Problemas**
   - Filtros por severidade, tipo, pasta, entidade
   - Sistema de busca em tempo real
   - Paginação e controle de registros por página
   - Badges coloridos para classificação visual

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

## 🔄 Versionamento

- Versão: 1.1.0
- Última atualização: 07/04/2025
- Changelog:
  - 1.1.0 - Adicionado dashboard HTML interativo
  - 1.0.1 - Melhorias no sistema de processamento em lotes
  - 1.0.0 - Versão inicial
