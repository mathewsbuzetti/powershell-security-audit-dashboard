# Script para Análise de Permissões e Geração de Dashboard
# Autor: Mathews Buzetti
# GitHub: https://github.com/mathewsbuzetti/powershell-security-audit-dashboard/blob/main/README.md
# Versão 1.1 - Com Dashboard HTML Moderno

param (
    [string]$ServerIP = "192.168.1.250",
    [array]$NetworkShares = @("\\$ServerIP\dados\Tree"),
    [string]$OutputPath = "C:\temp\SecurityAudit",
    [int]$MaxDepth = 3,
    [int]$BatchSize = 1000,
    [int]$MaxConcurrentJobs = 5,
    [array]$SkipFolders = @("$", "System Volume Information", "Recycle.Bin"),
    [switch]$GenerateHTML = $true
)

# Configuração de arquivos de saída
$OutFileCsv = "$OutputPath\NetworkPermissions.csv"
$LogFile = "$OutputPath\ScanLog.txt"
$HtmlReport = "$OutputPath\SecurityAnalysis.html"

# Configurações de exibição
$Compact = $true
$LogLevel = "Normal"
$global:TotalFoldersAll = 0
$global:TotalPermissionsAll = 0
$global:ErrorCountAll = 0
$global:UserPermissionsCount = 0
$global:ExcessivePermissionsCount = 0
$global:HeaderWritten = $false

# Criar diretório de saída se não existir
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Função para registrar log com diferentes níveis de severidade
function Write-Log {
    param (
        [string]$Message,
        [string]$Type = "INFO", # INFO, ERROR, WARNING, PROGRESS, RESULT
        [switch]$NoConsole
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Type] $Message"
    Add-Content -Path $LogFile -Value $logEntry
    
    if (-not $NoConsole) {
        if ($Type -eq "ERROR" -or 
            ($Type -eq "WARNING") -or
            ($LogLevel -eq "Verbose") -or 
            ($LogLevel -eq "Normal" -and $Type -ne "INFO") -or
            ($Type -eq "RESULT") -or
            ($Type -eq "SUMMARY")) {
            
            $timeStampPrefix = if ($Compact) { "" } else { "[$timestamp] " }
            
            switch ($Type) {
                "ERROR" { Write-Host "$timeStampPrefix[ERRO] $Message" -ForegroundColor Red }
                "WARNING" { Write-Host "$timeStampPrefix[AVISO] $Message" -ForegroundColor Yellow }
                "INFO" { Write-Host "$timeStampPrefix[INFO] $Message" -ForegroundColor Green }
                "PROGRESS" { Write-Host "$timeStampPrefix[...] $Message" -ForegroundColor Cyan }
                "RESULT" { Write-Host "$timeStampPrefix$Message" -ForegroundColor White }
                "SUMMARY" { Write-Host "$Message" -ForegroundColor White }
                Default { Write-Host "$timeStampPrefix$Message" -ForegroundColor White }
            }
        }
    }
}

# Limpar a tela para melhor visualização
Clear-Host

# Exibe cabeçalho do aplicativo com informações de versão e configuração
function Show-Header {
    if ($Compact) {
        Write-Host "┌─────────────────────────────────────────────────────┐" -ForegroundColor White
        Write-Host "│ SECURITY AUDIT SCANNER v1.1 [INTERACTIVE DASHBOARD] │" -ForegroundColor Green
        Write-Host "└─────────────────────────────────────────────────────┘" -ForegroundColor White        
    } else {
        Write-Host "┌─────────────────────────────────────────────────────────┐" -ForegroundColor White
        Write-Host "│              " -NoNewline -ForegroundColor White
        Write-Host "SECURITY AUDIT SCANNER v1.1 [INTERACTIVE DASHBOARD]" -NoNewline -ForegroundColor Green
        Write-Host "        │" -ForegroundColor White
        Write-Host "└─────────────────────────────────────────────────────────┘" -ForegroundColor White
        
        Write-Host ""
        Write-Host " [INICIANDO] " -NoNewline -ForegroundColor Yellow
        Write-Host "ESCANEAMENTO DE PERMISSÕES" -ForegroundColor White
        Write-Host ""
        Write-Host " CONFIGURAÇÃO ATUAL:" -ForegroundColor Green
        Write-Host " • Servidor:       " -NoNewline -ForegroundColor White
        Write-Host "$ServerIP" -ForegroundColor Yellow
        Write-Host " • Destino:        " -NoNewline -ForegroundColor White
        Write-Host "$OutputPath" -ForegroundColor Yellow
        Write-Host " • Profundidade:   " -NoNewline -ForegroundColor White
        Write-Host "$MaxDepth níveis" -ForegroundColor Yellow
        Write-Host " • Compartilhamentos: " -NoNewline -ForegroundColor White
        Write-Host "$($NetworkShares.Count)" -ForegroundColor Yellow
        Write-Host " • Versão:         " -NoNewline -ForegroundColor White
    }
}

# Inicialização de contadores de processamento
$global:TotalFolders = 0
$global:ProcessedFolders = 0
$global:TotalPermissions = 0
$global:ErrorCount = 0
$global:BatchCounter = 0
$global:StartTime = Get-Date

# Função para enumerar pastas recursivamente até uma profundidade máxima
function Get-FoldersRecursively {
    param (
        [string]$Path,
        [int]$CurrentDepth = 0,
        [int]$MaximumDepth
    )
    
    if ($CurrentDepth -gt $MaximumDepth) {
        return
    }
    
    try {
        $folders = Get-ChildItem -Path $Path -Directory -ErrorAction SilentlyContinue | 
                   Where-Object { $_.Name -notin $SkipFolders }
        
        foreach ($folder in $folders) {
            $global:TotalFolders++
            $folder
            Get-FoldersRecursively -Path $folder.FullName -CurrentDepth ($CurrentDepth + 1) -MaximumDepth $MaximumDepth
        }
    }
    catch {
        Write-Log -Message "Erro acessando $Path - $($_.Exception.Message)" -Type "ERROR"
        $global:ErrorCount++
    }
}

# Processa um lote de pastas e extrai suas ACLs
function Process-FolderBatch {
    param (
        [array]$Folders,
        [string]$OutputFile
    )
    
    $batchACLs = @()
    $processedCount = 0
    
    foreach ($folder in $Folders) {
        $processedCount++
        $global:ProcessedFolders++
        
        # Calcula e exibe progresso
        $percent = [math]::Min(100, [math]::Round(($global:ProcessedFolders / $global:TotalFolders) * 100, 1))
        $elapsedTime = (Get-Date) - $global:StartTime
        $estimatedTotalTime = $elapsedTime.TotalSeconds / ($global:ProcessedFolders / $global:TotalFolders)
        $remainingTime = $estimatedTotalTime - $elapsedTime.TotalSeconds
        $remainingTimeStr = [timespan]::FromSeconds($remainingTime).ToString("hh\:mm\:ss")
        
        # Define cor do progresso baseado na porcentagem
        $statusColor = if ($percent -lt 33) {
            "Red"
        } elseif ($percent -lt 66) {
            "Yellow"
        } else {
            "Green"
        }
        
        # Exibe atualizações de progresso em intervalos
        $displayInterval = if ($global:TotalFolders -lt 100) {
            [Math]::Max(1, [Math]::Round($global:TotalFolders / 10))
        } else {
            100
        }
        
        if ($processedCount % $displayInterval -eq 0 -or $global:ProcessedFolders -eq $global:TotalFolders) {
            Write-Host "Progresso: " -NoNewline
            Write-Host "$percent%" -ForegroundColor $statusColor -NoNewline
            Write-Host " - Pastas: $global:ProcessedFolders/$global:TotalFolders - Tempo restante: $remainingTimeStr"
        }
        
        # Atualiza barra de progresso
        Write-Progress -Activity "Escaneando permissões" -Status "Processando pastas" `
            -PercentComplete $percent `
            -CurrentOperation "Pasta $global:ProcessedFolders de $global:TotalFolders: $($folder.FullName)" `
            -SecondsRemaining $remainingTime
        
        try {
            # Obtém as ACLs para a pasta atual
            $acls = Get-Acl -Path $folder.FullName -ErrorAction SilentlyContinue | ForEach-Object { $_.Access }
            
            foreach ($acl in $acls) {
                $outInfo = [PSCustomObject]@{
                    FolderPath = $folder.FullName
                    IdentityReference = $acl.IdentityReference.ToString()
                    AccessControlType = $acl.AccessControlType.ToString()
                    IsInherited = $acl.IsInherited
                    InheritanceFlags = $acl.InheritanceFlags.ToString()
                    FileSystemRights = $acl.FileSystemRights.ToString()
                    PropagationFlags = $acl.PropagationFlags.ToString()
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
                
                $batchACLs += $outInfo
                $global:TotalPermissions++
            }
        }
        catch {
            Write-Log -Message "Erro obtendo ACLs para $($folder.FullName) - $($_.Exception.Message)" -Type "ERROR"
            $global:ErrorCount++
        }
    }
    
    # Exporta para CSV (append se não for o primeiro lote)
    if (-not $global:HeaderWritten) {
        $batchACLs | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
        $global:HeaderWritten = $true
    }
    else {
        $batchACLs | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8 -Append
    }
    
    $global:BatchCounter++
    Write-Log -Message "Exportado lote $global:BatchCounter com $($batchACLs.Count) permissões para $OutputFile"
    
    # Libera memória
    [System.GC]::Collect()
}

# Análise de permissões para geração do dashboard
function Analyze-Permissions {
    param (
        [string]$CsvPath
    )
    
    Write-Log -Message "Analisando permissões para dashboard HTML..."
    Write-Host " [ETAPA 3] " -NoNewline -ForegroundColor Yellow
    Write-Host "ANALISANDO PERMISSÕES PARA DASHBOARD" -ForegroundColor White

    # Importa dados do CSV
    $allPermissions = Import-Csv -Path $CsvPath
    Write-Log -Message "Importadas $($allPermissions.Count) permissões para análise"
    
    # Padrões para identificação de tipos de entidades
    $userPatterns = @('S-1-5-21-\d+-\d+-\d+-\d+$', 'DOMAIN\\[^\\]+$', '^[^\\]+\\[^\\]+$', 'NT AUTHORITY\\Usuário autenticado')
    $groupPatterns = @('BUILTIN\\', 'DOMAIN\\G_', 'DOMAIN\\GG_', 'NT AUTHORITY\\', 'CREATOR OWNER', 'S-1-5-32-', 
                       'PROPRIETÁRIO CRIADOR', 'SISTEMA', '.*\\Administradores', '.*\\Usuários', '\\.*Admins?$')
    $adminGroups = @('BUILTIN\\Administradores', 'Domain Admins', 'Enterprise Admins', '.*\\Administradores')
    
    # Inicialização de coleções para análise
    $userPermissions = @()
    $excessivePermissions = @()
    $inheritanceBroken = @()
    $allProblems = @()
    
    # Contagem de permissões por entidade
    $identityPermissionCount = @{}
    
    # Análise de cada permissão
    foreach ($perm in $allPermissions) {
        $identity = $perm.IdentityReference
        $isUser = $false
        $isGroup = $false
        $hasFullControl = $false
        
        # Contabiliza permissões por identidade
        if (-not $identityPermissionCount.ContainsKey($identity)) {
            $identityPermissionCount[$identity] = 0
        }
        $identityPermissionCount[$identity]++
        
        # Identifica grupos usando padrões
        foreach ($pattern in $groupPatterns) {
            if ($identity -match $pattern) {
                $isGroup = $true
                break
            }
        }
        
        # Identifica usuários se não for grupo
        if (-not $isGroup) {
            foreach ($pattern in $userPatterns) {
                if ($identity -match $pattern) {
                    $isUser = $true
                    break
                }
            }
        }
        
        # Verificação adicional para entidades não identificadas
        if (-not $isGroup -and -not $isUser) {
            if ($identity -match 'PROPRIETÁRIO|SISTEMA|Administradores|Usuários|\\Admin|CRIADOR') {
                $isGroup = $true
            }
            else {
                $isUser = $true
            }
        }
        
        # Verifica permissões de controle total
        if ($perm.FileSystemRights -like "*FullControl*" -and
            $identity -notmatch ($adminGroups -join '|')) {
            $hasFullControl = $true
        }
        
        # Adiciona à lista de problemas correspondente
        if ($isUser) {
            # Severidade Alta - Usuário direto
            $userPermissions += [PSCustomObject]@{
                Severity = "Alta"
                Type = "Usuário direto"
                FolderPath = $perm.FolderPath
                Identity = $identity
                Permission = $perm.FileSystemRights
                Recommendation = "Substituir por permissão de grupo"
                HasFullControl = $hasFullControl
            }
            
            $allProblems += $userPermissions[-1]
        } 
        elseif ($hasFullControl) {
            # Severidade Média - Grupos com permissões excessivas
            $excessivePermissions += [PSCustomObject]@{
                Severity = "Média"
                Type = "Grupos com permissões de risco"
                FolderPath = $perm.FolderPath
                Identity = $identity
                Permission = $perm.FileSystemRights
                Recommendation = "Reduzir para permissões mínimas necessárias"
                HasFullControl = $hasFullControl
            }
            
            $allProblems += $excessivePermissions[-1]
        }
        
        # Verifica quebra de herança
        if ($perm.IsInherited -eq $false -and -not $perm.FolderPath.EndsWith("\")) {
            $folderExists = $inheritanceBroken | Where-Object { $_.FolderPath -eq $perm.FolderPath }
            
            if (-not $folderExists) {
                $inheritanceBroken += [PSCustomObject]@{
                    Severity = "Baixa"
                    Type = "Quebra de herança desnecessária"
                    FolderPath = $perm.FolderPath
                    Identity = "N/A"
                    Permission = "N/A"
                    Recommendation = "Restaurar herança de permissões"
                    HasFullControl = $false
                }
                
                $allProblems += $inheritanceBroken[-1]
            }
        }
    }
    
    # Obtém Top 5 usuários/grupos com mais permissões
    $topIdentities = $identityPermissionCount.GetEnumerator() | 
                     Sort-Object -Property Value -Descending | 
                     Select-Object -First 5 | 
                     ForEach-Object {
                         [PSCustomObject]@{
                             Identity = $_.Key
                             PermissionCount = $_.Value
                         }
                     }
    
    # Contadores para o dashboard
    $global:UserPermissionsCount = $userPermissions.Count
    $global:ExcessivePermissionsCount = $excessivePermissions.Count
    $inheritanceBrokenCount = $inheritanceBroken.Count
    $totalProblems = $global:UserPermissionsCount + $global:ExcessivePermissionsCount + $inheritanceBrokenCount
    
    # Análise de conformidade AGDLP
    $agdlpCompliant = $allPermissions.Count - $userPermissions.Count - $excessivePermissions.Count
    $agdlpStats = @{
        TotalACLs = $allPermissions.Count
        CompliantACLs = $agdlpCompliant
        UserDirectPermissions = $userPermissions.Count
        NonCompliantGroups = $excessivePermissions.Count
        CompliantPercentage = [math]::Round(($agdlpCompliant / $allPermissions.Count) * 100, 1)
        UserPercentage = [math]::Round(($userPermissions.Count / $allPermissions.Count) * 100, 1)
        NonCompliantGroupsPercentage = [math]::Round(($excessivePermissions.Count / $allPermissions.Count) * 100, 1)
    }
    
    # Calcula índice de risco geral
    $riskIndex = [math]::Min(100, [math]::Round(($totalProblems / $allPermissions.Count) * 100))
    
    # Retorna resultados completos da análise
    $result = @{
        TotalFolders = $global:TotalFoldersAll
        TotalPermissions = $global:TotalPermissionsAll
        TotalProblems = $totalProblems
        RiskIndex = $riskIndex
        UserPermissions = $userPermissions
        ExcessivePermissions = $excessivePermissions
        InheritanceBroken = $inheritanceBroken
        AllProblems = $allProblems
        AGDLPStats = $agdlpStats
        TopIdentities = $topIdentities
    }
    
    return $result
}

function Generate-HTMLReport {
    param (
        [object]$AnalysisData
    )
    
    Write-Log -Message "Gerando relatório HTML moderno..."
    Write-Host " [ETAPA 4] " -NoNewline -ForegroundColor Yellow
    Write-Host "GERANDO DASHBOARD HTML MODERNO" -ForegroundColor White

    # Data atual para o relatório
    $currentDate = Get-Date -Format "dd/MM/yyyy"

    # Calcular percentuais reais de severidade
    $highCount = $AnalysisData.UserPermissions.Count
    $mediumCount = $AnalysisData.ExcessivePermissions.Count
    $lowCount = $AnalysisData.InheritanceBroken.Count
    $total = $highCount + $mediumCount + $lowCount
    
    if ($total -gt 0) {
        $highPercent = [math]::Round(($highCount / $total) * 100)
        $mediumPercent = [math]::Round(($mediumCount / $total) * 100)
        $lowPercent = [math]::Round(($lowCount / $total) * 100)
        
        # Ajustar para garantir que a soma seja 100%
        $sumPercent = $highPercent + $mediumPercent + $lowPercent
        if ($sumPercent -ne 100) {
            # Adicionar a diferença ao maior valor
            $diff = 100 - $sumPercent
            if ($highCount -ge $mediumCount -and $highCount -ge $lowCount) {
                $highPercent += $diff
            } elseif ($mediumCount -ge $highCount -and $mediumCount -ge $lowCount) {
                $mediumPercent += $diff
            } else {
                $lowPercent += $diff
            }
        }
    } else {
        $highPercent = 0
        $mediumPercent = 0
        $lowPercent = 0
    }

    # Determinar nível de risco baseado no índice
    $riskLevel = if ($AnalysisData.RiskIndex -lt 25) {
        "Baixo Risco"
    } elseif ($AnalysisData.RiskIndex -lt 50) {
        "Risco Moderado"
    } elseif ($AnalysisData.RiskIndex -lt 75) {
        "Alto Risco"
    } else {
        "Risco Crítico"
    }
    
    $riskColor = if ($AnalysisData.RiskIndex -lt 25) {
        "#38a169" # verde
    } elseif ($AnalysisData.RiskIndex -lt 50) {
        "#f6ad55" # laranja
    } elseif ($AnalysisData.RiskIndex -lt 75) {
        "#e53e3e" # vermelho
    } else {
        "#cc0000" # vermelho escuro
    }

    # Template HTML para o dashboard
    $html = @"
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Análise de Segurança de Permissões</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js" integrity="sha512-ElRFoEQdI5Ht6kZvyzXhYG9NqjtkmlkfYk0wr6wHxU9JEHakS7UJZNeml5ALk+8IKlU6jDgMabC3vkumRokgJA==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            /* Esquema de cores Azure inspirado */
            --primary: #0078d4;
            --primary-light: #50b0e0;
            --primary-dark: #004578;
            --secondary: #2d3748;
            
            /* Cores para severidade */
            --high: #e53e3e;
            --medium: #f6ad55;
            --low: #38a169;
            
            /* Cores para tipos de problemas */
            --user-permission: #D32F2F;
            --inheritance-break: #8b5cf6;
            --excessive-permission: #f97316;
            
            /* Cores para tipos de entidades */
            --creator-owner: #CC0000; /* Vermelho escuro: PROPRIETÁRIO CRIADOR */
            --system: #FF0000; /* Vermelho intenso: AUTORIDADE NT\SISTEMA */
            --admin-group: #FF9900; /* Laranja: BUILTIN\Administradores */
            --users-group: #3366CC; /* Azul: BUILTIN\Usuários */
            --specific-user: #FFCC00; /* Amarelo: Usuários específicos */
            
            /* Cores de fundo e texto */
            --bg-main: #f0f3f8;
            --bg-card: #ffffff;
            --bg-card-hover: #f6f8ff;
            --bg-panel: #f8fafc;
            
            --text-primary: #1a202c;
            --text-secondary: #4a5568;
            --text-light: #f7fafc;
            
            /* Bordas e sombras */
            --border-color: #e2e8f0;
            --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.08);
            --shadow-md: 0 4px 10px rgba(0, 0, 0, 0.1);
            --shadow-lg: 0 10px 25px rgba(0, 0, 0, 0.15);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Oxygen, Ubuntu, sans-serif;
        }
        
        body {
            background-color: var(--bg-main);
            color: var(--text-primary);
            padding: 2rem;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        /* Cabeçalho */
        .page-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            padding: 1.75rem;
            border-radius: 16px;
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: var(--text-light);
            box-shadow: var(--shadow-lg);
            position: relative;
            overflow: hidden;
        }
        
        .page-header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-image: url("data:image/svg+xml,%3Csvg width='100' height='100' viewBox='0 0 100 100' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M11 18c3.866 0 7-3.134 7-7s-3.134-7-7-7-7 3.134-7 7 3.134 7 7 7zm48 25c3.866 0 7-3.134 7-7s-3.134-7-7-7-7 3.134-7 7 3.134 7 7 7zm-43-7c1.657 0 3-1.343 3-3s-1.343-3-3-3-3 1.343-3 3 1.343 3 3 3zm63 31c1.657 0 3-1.343 3-3s-1.343-3-3-3-3 1.343-3 3 1.343 3 3 3zM34 90c1.657 0 3-1.343 3-3s-1.343-3-3-3-3 1.343-3 3 1.343 3 3 3zm56-76c1.657 0 3-1.343 3-3s-1.343-3-3-3-3 1.343-3 3 1.343 3 3 3zM12 86c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm28-65c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm23-11c2.76 0 5-2.24 5-5s-2.24-5-5-5-5 2.24-5 5 2.24 5 5 5zm-6 60c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm29 22c2.76 0 5-2.24 5-5s-2.24-5-5-5-5 2.24-5 5 2.24 5 5 5zM32 63c2.76 0 5-2.24 5-5s-2.24-5-5-5-5 2.24-5 5 2.24 5 5 5zm57-13c2.76 0 5-2.24 5-5s-2.24-5-5-5-5 2.24-5 5 2.24 5 5 5zm-9-21c1.105 0 2-.895 2-2s-.895-2-2-2-2 .895-2 2 .895 2 2 2zM60 91c1.105 0 2-.895 2-2s-.895-2-2-2-2 .895-2 2 .895 2 2 2zM35 41c1.105 0 2-.895 2-2s-.895-2-2-2-2 .895-2 2 .895 2 2 2zM12 60c1.105 0 2-.895 2-2s-.895-2-2-2-2 .895-2 2 .895 2 2 2z' fill='%23ffffff' fill-opacity='0.1' fill-rule='evenodd'/%3E%3C/svg%3E");
            opacity: 0.5;
            z-index: 0;
        }
        
        .page-title {
            font-size: 28px;
            font-weight: 700;
            color: var(--text-light);
            position: relative;
            z-index: 1;
            text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .page-title i {
            font-size: 24px;
            color: rgba(255, 255, 255, 0.9);
        }
        
        .page-subtitle {
            color: rgba(255, 255, 255, 0.9);
            font-size: 16px;
            margin-top: 6px;
            position: relative;
            z-index: 1;
        }
        
        .page-actions {
            display: flex;
            align-items: center;
            gap: 1rem;
            position: relative;
            z-index: 1;
        }
        
        .server-tag {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 14px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.3s ease;
            background: rgba(255, 255, 255, 0.1);
            color: white;
            border: 1px solid rgba(255, 255, 255, 0.2);
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            backdrop-filter: blur(5px);
        }
        
        .server-tag i {
            color: rgba(255, 255, 255, 0.9);
        }
        
        /* Cards de métricas em uma linha */
        .metrics-row {
            display: flex;
            gap: 15px;
            margin-bottom: 30px;
            flex-wrap: wrap;
        }
        
        /* Layout de grid para os gráficos lado a lado */
        .charts-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 24px;
        }
        
        @media (max-width: 1200px) {
            .charts-grid {
                grid-template-columns: 1fr;
            }
        }
        
        /* Estilo para o sumário (summary) semelhante ao modelo */
        .summary-section {
            background-color: var(--bg-card);
            border-radius: 16px;
            box-shadow: var(--shadow-lg);
            border: 1px solid var(--border-color);
            margin-bottom: 2rem;
            overflow: hidden;
            background-image: url("data:image/svg+xml,%3Csvg width='100' height='100' viewBox='0 0 100 100' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M11 18c3.866 0 7-3.134 7-7s-3.134-7-7-7-7 3.134-7 7 3.134 7 7 7zm48 25c3.866 0 7-3.134 7-7s-3.134-7-7-7-7 3.134-7 7 3.134 7 7 7zm-43-7c1.657 0 3-1.343 3-3s-1.343-3-3-3-3 1.343-3 3 1.343 3 3 3zm63 31c1.657 0 3-1.343 3-3s-1.343-3-3-3-3 1.343-3 3 1.343 3 3 3zM34 90c1.657 0 3-1.343 3-3s-1.343-3-3-3-3 1.343-3 3 1.343 3 3 3zm56-76c1.657 0 3-1.343 3-3s-1.343-3-3-3-3 1.343-3 3 1.343 3 3 3zM12 86c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm28-65c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm23-11c2.76 0 5-2.24 5-5s-2.24-5-5-5-5 2.24-5 5 2.24 5 5 5zm-6 60c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm29 22c2.76 0 5-2.24 5-5s-2.24-5-5-5-5 2.24-5 5 2.24 5 5 5zM32 63c2.76 0 5-2.24 5-5s-2.24-5-5-5-5 2.24-5 5 2.24 5 5 5zm57-13c2.76 0 5-2.24 5-5s-2.24-5-5-5-5 2.24-5 5 2.24 5 5 5zm-9-21c1.105 0 2-.895 2-2s-.895-2-2-2-2 .895-2 2 .895 2 2 2zM60 91c1.105 0 2-.895 2-2s-.895-2-2-2-2 .895-2 2 .895 2 2 2zM35 41c1.105 0 2-.895 2-2s-.895-2-2-2-2 .895-2 2 .895 2 2 2zM12 60c1.105 0 2-.895 2-2s-.895-2-2-2-2 .895-2 2 .895 2 2 2z' fill='%2300a5de' fill-opacity='0.03' fill-rule='evenodd'/%3E%3C/svg%3E");
            background-position: center;
            background-size: 200px;
            transition: all 0.3s ease;
            animation: fadeIn 0.6s ease-out;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        @keyframes pulseGlow {
            0% { box-shadow: 0 0 5px rgba(0, 120, 212, 0.3); }
            50% { box-shadow: 0 0 15px rgba(0, 120, 212, 0.5); }
            100% { box-shadow: 0 0 5px rgba(0, 120, 212, 0.3); }
        }
        
        .summary-section:hover {
            box-shadow: 0 15px 30px rgba(0, 0, 0, 0.1);
            transform: translateY(-3px);
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 0;
        }
        
        .summary-metric {
            padding: 2.5rem;
            position: relative;
            display: flex;
            flex-direction: column;
            gap: 1.25rem;
            overflow: hidden;
            transition: all 0.3s ease;
        }
        
        .summary-metric:not(:last-child) {
            border-right: 1px solid var(--border-color);
        }
        
        .summary-metric:hover {
            background-color: rgba(0, 120, 212, 0.02);
        }
        
        .summary-metric::before {
            content: '';
            position: absolute;
            top: -10px;
            left: -10px;
            width: 30px;
            height: 30px;
            background-color: var(--primary);
            opacity: 0.1;
            border-radius: 50%;
            transform: scale(0);
            transition: transform 0.5s;
        }
        
        .summary-metric:hover::before {
            transform: scale(10);
        }
        
        .metric-top {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            position: relative;
            z-index: 1;
        }
        
        .metric-title {
            font-size: 15px;
            font-weight: 700;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            position: relative;
        }
        
        .metric-title::after {
            content: '';
            position: absolute;
            bottom: -6px;
            left: 0;
            width: 30px;
            height: 3px;
            background: linear-gradient(135deg, #0078d4 0%, #50b0e0 100%);
            border-radius: 3px;
            transition: width 0.3s ease;
        }
        
        .summary-metric:hover .metric-title::after {
            width: 60px;
        }
        
        .metric-icon {
            width: 46px;
            height: 46px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 20px;
            position: relative;
            z-index: 1;
            box-shadow: 0 10px 15px rgba(0, 0, 0, 0.1);
            transition: all 0.3s ease;
            animation: pulseGlow 3s infinite;
        }
        
        .summary-metric:hover .metric-icon {
            transform: scale(1.1) translateY(-5px);
        }
        
        .icon-folders {
            background: linear-gradient(135deg, #0078d4, #50b0e0);
        }
        
        .icon-permissions {
            background: linear-gradient(135deg, #10b981, #34d399);
        }
        
        .icon-issues {
            background: linear-gradient(135deg, #f59e0b, #f97316);
        }
        
        .icon-risk {
            background: linear-gradient(135deg, #cc0000, #ff0000);
        }
        
        .metric-value-section {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            position: relative;
            z-index: 1;
        }
        
        .metric-value {
            font-size: 2.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, #0078d4 0%, #50b0e0 100%);
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
            line-height: 1.1;
            transition: all 0.3s ease;
        }
        
        .summary-metric:hover .metric-value {
            transform: scale(1.05);
        }
        
        .metric-value.green {
            background: linear-gradient(135deg, #10b981, #34d399);
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .metric-value.orange {
            background: linear-gradient(135deg, #f59e0b, #f97316);
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .metric-value.red {
            background: linear-gradient(135deg, #cc0000, #ff0000);
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .metric-description {
            font-size: 14px;
            color: var(--text-secondary);
            max-width: 250px;
        }
        
        .metric-card {
            background-color: var(--bg-card);
            border-radius: 10px;
            box-shadow: var(--shadow-md);
            padding: 25px;
            position: relative;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            transition: all 0.3s ease;
            flex: 1;
            min-width: 220px;
        }
        
        .metric-card:hover {
            transform: translateY(-5px);
            box-shadow: var(--shadow-lg);
        }
        
        .metric-title {
            font-size: 14px;
            font-weight: 700;
            color: var(--text-secondary);
            text-transform: uppercase;
            position: relative;
            display: inline-block;
            margin-bottom: 15px;
        }
        
        .metric-title::after {
            content: '';
            position: absolute;
            bottom: -5px;
            left: 0;
            width: 40px;
            height: 3px;
            border-radius: 3px;
        }
        
        .pastas .metric-title::after {
            background-color: var(--primary);
        }
        
        .permissoes .metric-title::after {
            background-color: var(--low);
        }
        
        .problemas .metric-title::after {
            background-color: var(--excessive-permission);
        }
        
        .risco .metric-title::after {
            background-color: var(--high);
        }
        
        .metric-value {
            font-size: 40px;
            font-weight: 700;
            margin-bottom: 10px;
        }
        
        .pastas .metric-value {
            color: var(--primary);
        }
        
        .permissoes .metric-value {
            color: var(--low);
        }
        
        .problemas .metric-value {
            color: var(--excessive-permission);
        }
        
        .risco .metric-value {
            color: var(--high);
        }
        
        .metric-desc {
            font-size: 13px;
            color: var(--text-secondary);
            line-height: 1.4;
            word-wrap: break-word;
        }
        
        .metric-icon {
            position: absolute;
            top: 25px;
            right: 25px;
            width: 40px;
            height: 40px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 18px;
        }
        
        .pastas .metric-icon {
            background-color: var(--primary);
        }
        
        .permissoes .metric-icon {
            background-color: var(--low);
        }
        
        .problemas .metric-icon {
            background-color: var(--excessive-permission);
        }
        
        .risco .metric-icon {
            background-color: var(--high);
        }
        
        /* Seções de conteúdo */
        .chart-card {
            background-color: var(--bg-card);
            border-radius: 16px;
            box-shadow: var(--shadow-lg);
            border: 1px solid var(--border-color);
            overflow: hidden;
            margin-bottom: 24px;
            height: 100%;
            display: flex;
            flex-direction: column;
        }
        
        .chart-header {
            padding: 1.5rem;
            border-bottom: 1px solid var(--border-color);
            background: linear-gradient(to right, rgba(0, 120, 212, 0.05), transparent);
        }
        
        .chart-title {
            font-size: 18px;
            font-weight: 700;
            margin-bottom: 0.25rem;
            color: var(--primary);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .chart-title i {
            font-size: 16px;
        }
        
        .chart-subtitle {
            font-size: 14px;
            color: var(--text-secondary);
        }
        
        .chart-body {
            padding: 1.5rem;
            height: 350px;
            position: relative;
            display: flex;
            flex-direction: column;
            justify-content: center;
            flex-grow: 1;
        }
        
        .chart-legend {
            display: flex;
            flex-wrap: wrap;
            gap: 1rem;
            padding: 1.25rem;
            background-color: var(--bg-panel);
            border-top: 1px solid var(--border-color);
            white-space: nowrap;
            justify-content: center; /* Centraliza os itens da legenda horizontalmente */
        }
        
        .legend-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 13px;
            color: var(--text-secondary);
        }
        
        .legend-color {
            width: 12px;
            height: 12px;
            border-radius: 3px;
        }
        
        /* Barras horizontais para o gráfico */
        .chart-fallback {
            width: 100%;
            height: 100%;
            display: flex;
            flex-direction: column;
            justify-content: center;
            gap: 25px;
        }
        
        .chart-bar-container {
            display: flex;
            gap: 5px; /* Reduzido para dar mais espaço aos rótulos */
            align-items: center;
            margin-bottom: 15px;
            flex-wrap: nowrap; /* Impede a quebra para nova linha */
        }
        
        /* Estilo geral para labels de gráficos */
        .chart-label {
            width: 180px; /* Tamanho base para labels de gráficos */
            min-width: 180px; /* Garante largura mínima */
            font-size: 14px; /* Ajustado para melhor legibilidade */
            font-weight: 600;
            color: var(--text-secondary);
            white-space: nowrap; /* Impede quebra de texto */
            overflow: visible; /* Permite que o texto fique visível */
        }
        
        /* Estilo específico para o gráfico de Problemas por Tipo */
        .problema-chart-label {
            width: 250px; /* Aumentado para acomodar textos mais longos */
            min-width: 250px; /* Garante largura mínima maior */
            font-size: 14px;
            font-weight: 600;
            color: var(--text-secondary);
            white-space: nowrap;
            overflow: visible;
        }
        
        .chart-bar {
            flex-grow: 1;
            height: 35px;
            background-color: rgba(80, 176, 224, 0.2);
            border-radius: 6px;
            position: relative;
            overflow: hidden;
            box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.1);
        }
        
        .chart-bar-fill {
            height: 100%;
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            padding-right: 15px;
            color: white;
            font-weight: 600;
            font-size: 14px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            min-width: 40px; /* Garantir largura mínima para o número ser visível */
            position: relative;
        }
        
        .chart-bar-value {
            position: absolute;
            right: 15px;
            color: white;
            font-weight: 600;
            font-size: 14px;
            white-space: nowrap;
        }

        /* Novos estilos para seção de risco e barras horizontais */
        .section-header {
            background-color: #f8f9fc;
            padding: 15px 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .section-header-icon {
            color: #0078d4;
            font-size: 22px;
        }
        
        .section-header-text {
            flex: 1;
        }
        
        .section-header-title {
            margin: 0;
            color: #0078d4;
            font-size: 18px;
            font-weight: 600;
        }
        
        .section-header-subtitle {
            margin: 5px 0 0 0;
            color: #4a5568;
            font-size: 14px;
            font-weight: 400;
        }
        
        .risk-explanation {
            background-color: rgba(0, 120, 212, 0.05);
            border-left: 3px solid var(--primary);
            padding: 10px 12px;
            border-radius: 6px;
            font-size: 13px;
            color: var(--text-secondary);
            line-height: 1.4;
            margin-top: 15px;
        }
        
        .formula {
            background-color: rgba(0, 0, 0, 0.03);
            padding: 6px 8px;
            border-radius: 4px;
            font-family: monospace;
            margin: 8px 0;
            display: flex;
            justify-content: center;
        }
        
        .example {
            margin-top: 8px;
            font-size: 12px;
            color: var(--text-light);
        }
        
        .risk-levels {
            display: flex;
            justify-content: space-between;
            margin-top: 10px;
        }
        
        .risk-level {
            text-align: center;
            font-size: 11px;
            flex: 1;
        }
        
        .risk-level-title {
            font-weight: 600;
            margin-bottom: 2px;
        }
        
        .risk-level-range {
            color: var(--text-light);
        }
        
        .low {
            color: var(--low);
        }
        
        .moderate {
            color: var(--medium);
        }
        
        .high {
            color: var(--high);
        }
        
        .critical {
            color: #cc0000;
        }
        
        .bar-container {
            margin-bottom: 20px;
        }
        
        .bar-item {
            margin-bottom: 15px;
        }
        
        .bar-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 5px;
        }
        
        .bar-label {
            font-weight: 600;
            font-size: 14px;
        }
        
        .bar-value {
            font-size: 14px;
        }
        
        .bar-outer {
            height: 25px;
            background-color: #f1f1f1;
            border-radius: 20px;
            overflow: hidden;
        }
        
        .bar-inner {
            height: 100%;
            border-radius: 20px;
        }
        
        .bar-high {
            background-color: var(--high);
        }
        
        .bar-medium {
            background-color: var(--medium);
        }
        
        .bar-low {
            background-color: var(--low);
        }
        
        .bar-description {
            font-size: 12px;
            color: var(--text-secondary);
            margin-top: 5px;
            margin-left: 2px;
            font-style: italic;
        }

        /* Estilos para o bloco de risco centralizado */
        .risk-score-container {
            text-align: center;
            padding: 20px;
        }
        
        .risk-score {
            font-size: 80px;
            font-weight: 800;
            line-height: 1;
            color: var(--high);
            margin-bottom: 10px;
        }
        
        .risk-score-label {
            font-size: 24px;
            font-weight: 700;
            color: var(--high);
            margin-bottom: 5px;
        }
        
        .risk-score-sublabel {
            font-size: 14px;
            color: var(--text-secondary);
        }

        /* Estilo para os níveis de risco */
        .risk-ranges {
            display: flex;
            justify-content: space-between;
            margin-top: 15px;
            border-top: 1px solid #eaeaea;
            padding-top: 15px;
        }
        
        .risk-range {
            text-align: center;
            padding: 5px 0;
            flex: 1;
        }
        
        .risk-range-title {
            font-weight: 700;
            font-size: 14px;
            margin-bottom: 4px;
        }
        
        .risk-range-values {
            font-size: 13px;
            color: var(--text-secondary);
        }
        
        .risk-range.baixo .risk-range-title {
            color: var(--low);
        }
        
        .risk-range.moderado .risk-range-title {
            color: var(--medium);
        }
        
        .risk-range.alto .risk-range-title {
            color: var(--high);
        }
        
        .risk-range.critico .risk-range-title {
            color: #cc0000;
        }
        
        /* Todos os Problemas */
        .table-section {
            background-color: var(--bg-card);
            border-radius: 16px;
            box-shadow: var(--shadow-lg);
            border: 1px solid var(--border-color);
            margin-bottom: 2rem;
            overflow: hidden;
        }
        
        .table-header {
            padding: 1.5rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: linear-gradient(to right, rgba(0, 120, 212, 0.05), transparent);
        }
        
        .table-title {
            font-size: 18px;
            font-weight: 700;
            margin-bottom: 0.25rem;
            color: var(--primary);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .table-title i {
            font-size: 16px;
        }
        
        .table-subtitle {
            font-size: 14px;
            color: var(--text-secondary);
        }
        
        .table-controls {
            display: flex;
            gap: 0.75rem;
        }
        
        .table-search {
            display: flex;
            align-items: center;
            gap: 8px;
            background: var(--bg-panel);
            border: 1px solid var(--border-color);
            padding: 8px 16px;
            border-radius: 10px;
            box-shadow: var(--shadow-sm);
            width: 300px;
        }
        
        .table-search-icon {
            color: var(--primary);
            font-size: 14px;
        }
        
        .table-search-input {
            background: transparent;
            border: none;
            color: var(--text-primary);
            font-size: 14px;
            outline: none;
            width: 100%;
            padding: 4px 0;
        }
        
        /* Estilo para filtros */
        .filter-section {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin: 0 1.5rem 0.75rem;
            padding: 10px;
            background-color: #f8f9fa;
            border-radius: 8px;
            border: 1px solid #e9ecef;
        }
        
        .filter-field {
            flex: 1;
            min-width: 200px;
        }
        
        .filter-label {
            display: block;
            font-size: 13px;
            font-weight: 600;
            color: #515a6e;
            margin-bottom: 5px;
        }
        
        .filter-select {
            width: 100%;
            padding: 8px 12px;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
            font-size: 14px;
            color: #333;
            background-color: #fff;
        }
        
        .filter-buttons {
            display: flex;
            gap: 10px;
            margin: 0 1.5rem 1.5rem;
        }
        
        .filter-apply {
            padding: 8px 16px;
            border: none;
            border-radius: 4px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            background-color: #0288d1;
            color: white;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .filter-clear {
            padding: 8px 16px;
            background-color: #f5f5f5;
            color: #515a6e;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        /* Tabela de problemas */
        .table-body {
            padding: 0.5rem 1.5rem;
        }
        
        .security-table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            border: 1px solid var(--border-color);
        }
        
        .security-table th {
            background: #f5f7fa;
            color: var(--primary);
            font-weight: 600;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 8px 16px;
            text-align: left;
            border-bottom: 2px solid var(--border-color);
            position: relative;
            vertical-align: middle;
        }
        
        .security-table td {
            padding: 14px 16px;
            font-size: 14px;
            border-bottom: 1px solid var(--border-color);
        }
        
        .security-table tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        
        .security-table tr:hover {
            background-color: #f0f8ff;
        }
        
        /* Badges */
        .severity-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.05);
        }
        
        .severity-badge i {
            font-size: 11px;
        }
        
        .badge-high {
            background: rgba(229, 62, 62, 0.1);
            color: var(--high);
            border: 1px solid rgba(229, 62, 62, 0.2);
        }
        
        .badge-medium {
            background: rgba(246, 173, 85, 0.1);
            color: var(--medium);
            border: 1px solid rgba(246, 173, 85, 0.2);
        }
        
        .badge-low {
            background: rgba(56, 161, 105, 0.1);
            color: var(--low);
            border: 1px solid rgba(56, 161, 105, 0.2);
        }
        
        .problem-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.05);
        }
        
        .problem-badge i {
            font-size: 11px;
        }
        
        .badge-loose-user {
            background: rgba(211, 47, 47, 0.1);
            color: var(--user-permission);
            border: 1px solid rgba(211, 47, 47, 0.2);
        }
        
        .badge-excessive {
            background: rgba(249, 115, 22, 0.1);
            color: var(--excessive-permission);
            border: 1px solid rgba(249, 115, 22, 0.2);
        }
        
        .badge-inheritance {
            background: rgba(139, 92, 246, 0.1);
            color: var(--inheritance-break);
            border: 1px solid rgba(139, 92, 246, 0.2);
        }
        
        /* Paginação e controles de registros por página */
        .table-footer {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 1.5rem;
            border-top: 1px solid var(--border-color);
            background-color: #f8f9fa;
        }
        
        .entries-info-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 1.5rem;
            background-color: #f8f9fa;
            border-top: 1px solid var(--border-color);
        }
        
        .entries-per-page {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 13px;
            color: var(--text-secondary);
            white-space: nowrap;
        }
        
        .entries-select {
            padding: 6px 10px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            font-size: 13px;
            color: var(--text-primary);
            background-color: white;
        }
        
        .table-info {
            margin: 0;
            padding: 10px 0;
            font-size: 13px;
            color: #515a6e;
            text-align: right;
            white-space: nowrap;
        }
        
        .pagination-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 1.5rem;
            background-color: #f8f9fa;
            border-bottom-left-radius: 16px;
            border-bottom-right-radius: 16px;
            border-top: 1px solid var(--border-color);
        }
        
        .pagination-info {
            font-size: 13px;
            color: #515a6e;
            white-space: nowrap;
        }
        
        .pagination {
            display: flex;
            gap: 5px;
        }
        
        .pagination-button {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 6px 12px;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
            background-color: white;
            font-size: 14px;
            color: #515a6e;
            cursor: pointer;
            min-width: 35px;
            transition: all 0.2s ease;
        }
        
        .pagination-button:hover {
            background-color: #f0f2f5;
        }
        
        .pagination-button.active {
            background-color: #0288d1;
            color: white;
            border-color: #0288d1;
        }
        
        .pagination-button.disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        
        /* Footer */
        .footer {
            text-align: center;
            padding: 20px 0;
            margin-top: 30px;
            border-top: 1px solid var(--border-color);
            color: var(--text-secondary);
            font-size: 13px;
            background: linear-gradient(to right, rgba(0, 120, 212, 0.03), transparent, rgba(0, 120, 212, 0.03));
            position: relative;
            overflow: hidden;
        }
        
        .footer::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 3px;
            background: linear-gradient(135deg, #0078d4 0%, #50b0e0 100%);
            opacity: 0.5;
        }
        
        .dashboard-title {
            color: var(--primary);
            font-weight: bold;
            transition: all 0.3s ease;
        }
        
        .dashboard-title:hover {
            color: var(--primary-dark);
            text-shadow: 0 2px 10px rgba(0, 120, 212, 0.3);
        }
        
        /* Responsividade */
        @media (max-width: 1200px) {
            .metrics-row {
                flex-wrap: wrap;
            }
            
            .metric-card {
                flex-basis: calc(50% - 15px);
                flex-grow: 1;
            }
        }
        
        @media (max-width: 768px) {
            .page-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 20px;
            }
            
            .server-tag {
                width: 100%;
            }
            
            .metrics-row {
                flex-direction: column;
            }
            
            .metric-card {
                flex-basis: 100%;
            }
            
            .table-header {
                flex-direction: column;
                gap: 10px;
                align-items: flex-start;
            }
            
            .table-controls {
                width: 100%;
            }
            
            .filter-section {
                flex-direction: column;
            }
            
            .table-search {
                width: 100%;
            }
            
            body {
                padding: 10px;
            }
        }
        
        /* Estilos para a seção de Pontuação de Risco e Distribuição de Severidade */
        .risk-content {
            display: flex;
            flex-wrap: wrap;
            gap: 0;
        }
        
        /* Seção de pontuação */
        .risk-score-section {
            flex: 1;
            min-width: 220px;
            padding: 1rem;
            border-right: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }
        
        .risk-score-container {
            text-align: center;
            padding: 0.5rem 0.5rem;
        }
        
        .risk-score {
            font-size: 65px;
            font-weight: 800;
            line-height: 1;
            color: var(--high);
            margin-bottom: 0;
        }
        
        .risk-score-label {
            font-size: 22px;
            font-weight: 700;
            color: var(--high);
            margin: 0.25rem 0;
        }
        
        .risk-score-sublabel {
            font-size: 13px;
            color: var(--text-secondary);
        }
        
        .risk-explanation {
            background-color: rgba(0, 120, 212, 0.05);
            border-left: 3px solid var(--primary);
            padding: 8px 10px;
            border-radius: 6px;
            font-size: 12.5px;
            color: var(--text-secondary);
            line-height: 1.4;
            width: 100%;
            margin-top: 12px;
        }
        
        .formula {
            background-color: rgba(0, 0, 0, 0.03);
            padding: 5px 7px;
            border-radius: 4px;
            font-family: monospace;
            margin: 6px 0;
            display: flex;
            justify-content: center;
        }
        
        /* Níveis de risco */
        .risk-ranges {
            display: flex;
            justify-content: space-between;
            margin-top: 12px;
            border-top: 1px solid #eaeaea;
            padding-top: 8px;
            width: 100%;
        }
        
        .risk-range {
            text-align: center;
            padding: 3px 0;
            flex: 1;
        }
        
        .risk-range-title {
            font-weight: 700;
            font-size: 13px;
            margin-bottom: 2px;
        }
        
        .risk-range-values {
            font-size: 12px;
            color: var(--text-secondary);
        }
        
        .risk-range.baixo .risk-range-title {
            color: var(--low);
        }
        
        .risk-range.moderado .risk-range-title {
            color: var(--medium);
        }
        
        .risk-range.alto .risk-range-title {
            color: var(--high);
        }
        
        .risk-range.critico .risk-range-title {
            color: #cc0000;
        }
        
        /* Seção de Distribuição de Severidade */
        .severity-distribution {
            flex: 2;
            min-width: 300px;
            padding: 1rem;
            display: flex;
            flex-direction: column;
        }
        
        .distribution-title {
            font-size: 16px;
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 10px;
            text-align: center;
        }
        
        .chart-fallback {
            width: 100%;
            height: 100%;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }
        
        .chart-group {
            margin-bottom: 12px;
        }
        
        .chart-group:first-child {
            margin-top: 2px;
        }
        
        .chart-bar-container {
            display: flex;
            gap: 15px;
            align-items: center;
            margin-bottom: 5px;
            flex-wrap: nowrap; /* Impede a quebra para nova linha */
        }
        
        .chart-label {
            width: 120px;
            min-width: 120px; /* Garante largura mínima */
            font-size: 13.5px;
            font-weight: 500;
            color: var(--text-secondary);
            white-space: nowrap; /* Impede quebra de texto */
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .chart-bar {
            flex-grow: 1;
            height: 30px;
            background-color: rgba(80, 176, 224, 0.1);
            border-radius: 6px;
            position: relative;
            overflow: visible; /* Alterado para permitir que o texto ultrapasse os limites */
            box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.08);
        }
        
        .chart-bar-fill {
            height: 100%;
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: flex-start;
            padding-left: 10px;
            color: white;
            font-weight: 600;
            font-size: 13px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            min-width: 90px; /* Aumento do tamanho mínimo para acomodar texto */
            position: relative;
            overflow: visible; /* Permite que o texto ultrapasse os limites */
        }
        
        .chart-bar-value {
            display: flex;
            align-items: center;
            gap: 5px;
            white-space: nowrap;
        }
        
        .bar-description {
            font-size: 11px;
            color: var(--text-secondary);
            margin-top: 2px;
            margin-left: 135px;
            font-style: italic;
        }
        
        @media (max-width: 768px) {
            .risk-content {
                flex-direction: column;
            }
            
            .risk-score-section {
                border-right: none;
                border-bottom: 1px solid var(--border-color);
            }
            
            .chart-label {
                width: 110px;
            }
            
            .bar-description {
                margin-left: 125px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Cabeçalho com ícone -->
        <div class="page-header">
            <div>
                <h1 class="page-title"><i class="fas fa-shield-alt"></i> Análise de Segurança de Permissões</h1>
                <p class="page-subtitle">Visualização e análise de permissões em compartilhamentos de rede</p>
            </div>
            <div class="page-actions">
                <div>
                    <span class="server-tag"><i class="fas fa-server"></i> Servidor: $ServerIP</span>
                    <span class="server-tag"><i class="fas fa-folder-open"></i> Compartilhamentos: $($NetworkShares.Count)</span>
                </div>
            </div>
        </div>
        
        <!-- Summary Section - Estilo modelo -->
        <div class="summary-section">
            <div class="summary-grid">
                <!-- Pastas Analisadas -->
                <div class="summary-metric">
                    <div class="metric-top">
                        <div class="metric-title">Pastas Analisadas</div>
                        <div class="metric-icon icon-folders">
                            <i class="fas fa-folder"></i>
                        </div>
                    </div>
                    <div class="metric-value-section">
                        <div class="metric-value" id="folders-count">$($AnalysisData.TotalFolders)</div>
                        <div class="metric-description">Total de pastas escaneadas em todos os compartilhamentos</div>
                    </div>
                </div>
                
                <!-- Total de Permissões -->
                <div class="summary-metric">
                    <div class="metric-top">
                        <div class="metric-title">Permissões Totais</div>
                        <div class="metric-icon icon-permissions">
                            <i class="fas fa-key"></i>
                        </div>
                    </div>
                    <div class="metric-value-section">
                        <div class="metric-value green" id="permissions-count">$($AnalysisData.TotalPermissions)</div>
                        <div class="metric-description">Entradas de controle de acesso encontradas</div>
                    </div>
                </div>
                
                <!-- Problemas Detectados -->
                <div class="summary-metric">
                    <div class="metric-top">
                        <div class="metric-title">Problemas Detectados</div>
                        <div class="metric-icon icon-issues">
                            <i class="fas fa-exclamation-triangle"></i>
                        </div>
                    </div>
                    <div class="metric-value-section">
                        <div class="metric-value orange" id="issues-count">$($AnalysisData.TotalProblems)</div>
                        <div class="metric-description">Questões de segurança identificadas</div>
                    </div>
                </div>
                
                <!-- Índice de Risco -->
                <div class="summary-metric">
                    <div class="metric-top">
                        <div class="metric-title">Índice de Risco</div>
                        <div class="metric-icon icon-risk">
                            <i class="fas fa-chart-line"></i>
                        </div>
                    </div>
                    <div class="metric-value-section">
                        <div class="metric-value red" id="risk-index">$($AnalysisData.RiskIndex)</div>
                        <div class="metric-description">Avaliação geral de risco de segurança (0-100)</div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Gráficos lado a lado - Problemas por Tipo e Top 5 Usuários/Grupos -->
        <div class="charts-grid">
            <!-- Problemas por Tipo -->
            <div class="chart-card">
                <div class="chart-header">
                    <h3 class="chart-title"><i class="fas fa-chart-pie"></i> Problemas por Tipo</h3>
                    <p class="chart-subtitle">Distribuição dos problemas de segurança por categoria</p>
                </div>
                <div class="chart-body">
                    <div class="chart-fallback">
                        <!-- Permissão de usuário direto -->
                        <div class="chart-bar-container">
                            <div class="problema-chart-label" title="Permissão de usuário direto">Permissão de usuário direto:</div>
                            <div class="chart-bar">
                                <div class="chart-bar-fill" style="width: $([math]::Max(5, [math]::Round($AnalysisData.UserPermissions.Count / $AnalysisData.TotalProblems * 100)))%; background-color: var(--user-permission);">
                                    <span class="chart-bar-value">$($AnalysisData.UserPermissions.Count)</span>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Grupos com permissões de risco -->
                        <div class="chart-bar-container">
                            <div class="problema-chart-label" title="Grupos com permissões de risco">Grupos com permissões de risco:</div>
                            <div class="chart-bar">
                                <div class="chart-bar-fill" style="width: $([math]::Max(5, [math]::Round($AnalysisData.ExcessivePermissions.Count / $AnalysisData.TotalProblems * 100)))%; background-color: var(--excessive-permission);">
                                    <span class="chart-bar-value">$($AnalysisData.ExcessivePermissions.Count)</span>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Quebra de herança desnecessária -->
                        <div class="chart-bar-container">
                            <div class="problema-chart-label" title="Quebra de herança desnecessária">Quebra de herança desnecessária:</div>
                            <div class="chart-bar">
                                <div class="chart-bar-fill" style="width: $([math]::Max(5, [math]::Round($AnalysisData.InheritanceBroken.Count / $AnalysisData.TotalProblems * 100)))%; background-color: var(--inheritance-break);">
                                    <span class="chart-bar-value">$($AnalysisData.InheritanceBroken.Count)</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="chart-legend">
                    <div class="legend-item">
                        <div class="legend-color" style="background-color: var(--user-permission);"></div>
                        <span>Permissão de usuário direto: $($AnalysisData.UserPermissions.Count)</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background-color: var(--excessive-permission);"></div>
                        <span>Grupos com permissões de risco: $($AnalysisData.ExcessivePermissions.Count)</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background-color: var(--inheritance-break);"></div>
                        <span>Quebra de herança desnecessária: $($AnalysisData.InheritanceBroken.Count)</span>
                    </div>
                </div>
            </div>

            <!-- Top 5 Usuários/Grupos com Mais Permissões -->
            <div class="chart-card">
                <div class="chart-header">
                    <h3 class="chart-title"><i class="fas fa-users"></i> Top 5 Usuários/Grupos com Mais Permissões</h3>
                    <p class="chart-subtitle">Entidades com maior número de permissões no ambiente</p>
                </div>
                <div class="chart-body">
                    <div class="chart-fallback">
                        <!-- Barras horizontais para top 5 usuários/grupos -->
                        $($topEntitiesBarChart = "")
                        $(
                            # Função para determinar o tipo de entidade e cor apropriada
                            function Get-EntityColorAndType {
                                param (
                                    [string]$EntityName
                                )
                                
                                # Inicializar com valores padrão
                                $colorCode = "#FFCC00" # Amarelo para usuário específico 
                                $entityType = "Usuário específico"
                                
                                # Detectar tipo de entidade
                                if ($EntityName -match "PROPRIETÁRIO CRIADOR|CREATOR OWNER") {
                                    $colorCode = "#CC0000" # Vermelho escuro
                                    $entityType = "Conta Especial/Sistema"
                                }
                                elseif ($EntityName -match "SISTEMA|NT AUTHORITY\\SYSTEM") {
                                    $colorCode = "#FF0000" # Vermelho intenso
                                    $entityType = "Conta do Sistema Operacional"
                                }
                                elseif ($EntityName -match "BUILTIN\\Administradores|Domain Admins|Enterprise Admins") {
                                    $colorCode = "#FF9900" # Laranja
                                    $entityType = "Grupo administrativo"
                                }
                                elseif ($EntityName -match "BUILTIN\\Usuários|Users") {
                                    $colorCode = "#3366CC" # Azul
                                    $entityType = "Grupo padrão de usuários"
                                }
                                
                                return @{
                                    Color = $colorCode
                                    Type = $entityType
                                }
                            }
                            
                            # Obter o maior valor para calcular as porcentagens
                            $maxPermissions = if ($AnalysisData.TopIdentities.Count -gt 0) { 
                                ($AnalysisData.TopIdentities | Sort-Object -Property PermissionCount -Descending | Select-Object -First 1).PermissionCount 
                            } else { 
                                1 
                            }
                            
                            # Limitar a 5 entidades
                            $topIdentities = $AnalysisData.TopIdentities | Select-Object -First 5
                            
                            # Gerar as barras para cada entidade
                            $count = 0
                            foreach ($entity in $topIdentities) {
                                $count++
                                $percentWidth = [math]::Max(5, [math]::Round(($entity.PermissionCount / $maxPermissions) * 100))
                                
                                # Determinar cor e tipo da entidade
                                $entityInfo = Get-EntityColorAndType -EntityName $entity.Identity
                                $barColor = $entityInfo.Color
                                $entityType = $entityInfo.Type
                                
                                # Exibir o nome da entidade com uma única barra invertida
                                $displayIdentity = $entity.Identity -replace '\\\\', '\'
                                
                                $valueJustify = if ($entity.PermissionCount -lt 50) { "flex-start" } else { "flex-end" }
                                $textColor = "white"
                                $minBarWidth = "40px"
                                
                                $barHtml = @"
                                <div style="display: flex; align-items: center; margin-bottom: 15px; gap: 10px;">
                                    <div style="width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 14px; font-weight: bold; color: var(--text-secondary);">$displayIdentity</div>
                                    <div style="flex-grow: 1; position: relative; height: 30px;">
                                        <div style="position: absolute; left: 0; top: 0; width: 100%; height: 100%; background-color: #d6efff; border-radius: 6px;"></div>
                                        <div style="position: absolute; left: 0; top: 0; height: 100%; width: $percentWidth%; min-width: $minBarWidth; background-color: $barColor; border-radius: 6px; display: flex; align-items: center; justify-content: $valueJustify; padding: 0 10px; color: $textColor; font-weight: 600; font-size: 14px; z-index: 2;">
                                            $($entity.PermissionCount)
                                        </div>
                                    </div>
                                </div>
"@
                                $topEntitiesBarChart += $barHtml
                            }
                            
                            $topEntitiesBarChart
                        )
                    </div>
                </div>
                <div class="chart-legend">
                    $(
                        # Inicializar contadores por tipo
                        $entityCountsByType = @{
                            "Conta Especial/Sistema" = 0
                            "Conta do Sistema Operacional" = 0
                            "Grupo administrativo" = 0
                            "Grupo padrão de usuários" = 0
                            "Usuário específico" = 0
                        }
                        
                        # Calcular a soma de permissões por tipo (não apenas contar entidades)
                        foreach ($entity in $AnalysisData.TopIdentities) {
                            $entityInfo = Get-EntityColorAndType -EntityName $entity.Identity
                            $entityType = $entityInfo.Type
                            # Somamos o número real de permissões, não apenas incrementamos o contador
                            $entityCountsByType[$entityType] += $entity.PermissionCount
                        }
                    )
                    <div class="legend-item">
                        <div class="legend-color" style="background-color: #CC0000;"></div>
                        <span>Conta Especial/Sistema: $($entityCountsByType["Conta Especial/Sistema"])</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background-color: #FF0000;"></div>
                        <span>Conta do Sistema Operacional: $($entityCountsByType["Conta do Sistema Operacional"])</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background-color: #FF9900;"></div>
                        <span>Grupo administrativo: $($entityCountsByType["Grupo administrativo"])</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background-color: #3366CC;"></div>
                        <span>Grupo padrão de usuários: $($entityCountsByType["Grupo padrão de usuários"])</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background-color: #FFCC00;"></div>
                        <span>Usuário específico: $($entityCountsByType["Usuário específico"])</span>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- NOVA SEÇÃO: Pontuação de Risco e Distribuição de Severidade -->
        <div class="chart-card" style="margin-bottom: 24px;">
            <div class="chart-header" style="background: linear-gradient(to right, rgba(0, 120, 212, 0.08), transparent);">
                <div style="display: flex; gap: 10px; align-items: center;">
                    <div style="width: 28px; height: 28px; border-radius: 8px; background-color: rgba(0, 120, 212, 0.1); display: flex; align-items: center; justify-content: center;">
                        <i class="fas fa-chart-pie" style="color: var(--primary);"></i>
                    </div>
                    <div>
                        <h3 class="chart-title">Pontuação de Risco e Distribuição de Severidade</h3>
                        <p class="chart-subtitle">Análise detalhada da severidade dos problemas de segurança</p>
                    </div>
                </div>
            </div>
            
            <div class="chart-body" style="height: auto; padding: 0;">
                <div class="risk-content">
                    <!-- Seção de Pontuação de Risco -->
                    <div class="risk-score-section">
                        <div class="risk-score-container">
                            <div class="risk-score" style="color: $riskColor;">$($AnalysisData.RiskIndex)</div>
                            <div class="risk-score-label" style="color: $riskColor;">$riskLevel</div>
                            <div class="risk-score-sublabel">Índice de Risco Geral</div>
                        </div>
                        
                        <div class="risk-explanation">
                            <p>Este valor representa a porcentagem de permissões com problemas de segurança.</p>
                            <div class="formula">
                                Índice = (Problemas ÷ Permissões) × 100
                            </div>
                            
                            <!-- Níveis de risco em uma linha -->
                            <div class="risk-ranges">
                                <div class="risk-range baixo">
                                    <div class="risk-range-title">Baixo</div>
                                    <div class="risk-range-values">0-25</div>
                                </div>
                                <div class="risk-range moderado">
                                    <div class="risk-range-title">Moderado</div>
                                    <div class="risk-range-values">26-50</div>
                                </div>
                                <div class="risk-range alto">
                                    <div class="risk-range-title">Alto</div>
                                    <div class="risk-range-values">51-75</div>
                                </div>
                                <div class="risk-range critico">
                                    <div class="risk-range-title">Crítico</div>
                                    <div class="risk-range-values">76-100</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Seção de Distribuição de Severidade -->
                    <div class="severity-distribution">
                        <div class="distribution-title">Distribuição de Severidade</div>
                        <div class="chart-fallback">
                            <!-- Alto Impacto -->
                            <div class="chart-group">
                                <div class="chart-bar-container">
                                    <div class="chart-label">Alto Impacto:</div>
                                    <div class="chart-bar">
                                        <div class="chart-bar-fill" style="width: $([math]::Max(5, $highPercent))%; background-color: var(--high);">
                                            <span class="chart-bar-value">$highCount <small>($highPercent%)</small></span>
                                        </div>
                                    </div>
                                </div>
                                <div class="bar-description">Acesso direto e permissões excessivas</div>
                            </div>
                            
                            <!-- Médio Impacto -->
                            <div class="chart-group">
                                <div class="chart-bar-container">
                                    <div class="chart-label">Médio Impacto:</div>
                                    <div class="chart-bar">
                                        <div class="chart-bar-fill" style="width: $([math]::Max(5, $mediumPercent))%; background-color: var(--medium);">
                                            <span class="chart-bar-value">$mediumCount <small>($mediumPercent%)</small></span>
                                        </div>
                                    </div>
                                </div>
                                <div class="bar-description">Configurações de risco moderado</div>
                            </div>
                            
                            <!-- Baixo Impacto -->
                            <div class="chart-group">
                                <div class="chart-bar-container">
                                    <div class="chart-label">Baixo Impacto:</div>
                                    <div class="chart-bar">
                                        <div class="chart-bar-fill" style="width: $([math]::Max(5, $lowPercent))%; background-color: var(--low);">
                                            <span class="chart-bar-value">$lowCount <small>($lowPercent%)</small></span>
                                        </div>
                                    </div>
                                </div>
                                <div class="bar-description">Questões de otimização</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Legenda -->
            <div class="chart-legend">
                <div class="legend-item">
                    <div class="legend-color" style="background-color: var(--high);"></div>
                    <span>Alto Impacto: $highCount ($highPercent%)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background-color: var(--medium);"></div>
                    <span>Médio Impacto: $mediumCount ($mediumPercent%)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background-color: var(--low);"></div>
                    <span>Baixo Impacto: $lowCount ($lowPercent%)</span>
                </div>
            </div>
        </div>
        
        <!-- SEÇÃO: Insights sobre Configurações de Acesso Seguras -->
        <div class="chart-card" style="margin-bottom: 24px;">
            <div class="chart-header">
                <h3 class="chart-title"><i class="fas fa-lightbulb"></i> Insights de Segurança e Recomendações</h3>
                <p class="chart-subtitle">Análise das configurações atuais e sugestões para melhoria</p>
            </div>
            <div class="chart-body" style="height: auto; padding: 0;">
                <div style="padding: 20px;">
                    <h4 style="font-size: 18px; margin-bottom: 16px; color: var(--primary);">Recomendações Personalizadas</h4>
                    
                    <div id="insights-container">
                        <!-- Insight 1: Alta Prioridade -->
                        <div style="display: flex; gap: 15px; padding: 16px; margin-bottom: 16px; border-radius: 8px; background-color: rgba(229, 62, 62, 0.05); border-left: 4px solid var(--high); box-shadow: var(--shadow-sm);">
                            <div style="min-width: 36px; min-height: 36px; border-radius: 50%; background-color: rgba(229, 62, 62, 0.1); color: var(--high); display: flex; align-items: center; justify-content: center;">
                                <i class="fas fa-user-shield"></i>
                            </div>
                            <div>
                                <h5 style="font-size: 16px; margin-bottom: 5px; font-weight: 600; color: var(--high);">Revisar permissões de usuário direto</h5>
                                <p style="font-size: 14px; color: var(--text-secondary); margin: 0;">Foram encontradas $($AnalysisData.UserPermissions.Count) instâncias de permissões atribuídas diretamente a usuários. Recomendamos substituir por grupos para facilitar a gestão.</p>
                            </div>
                        </div>
                        
                        <!-- Insight 2: Média Prioridade -->
                        <div style="display: flex; gap: 15px; padding: 16px; margin-bottom: 16px; border-radius: 8px; background-color: rgba(246, 173, 85, 0.05); border-left: 4px solid var(--medium); box-shadow: var(--shadow-sm);">
                            <div style="min-width: 36px; min-height: 36px; border-radius: 50%; background-color: rgba(246, 173, 85, 0.1); color: var(--medium); display: flex; align-items: center; justify-content: center;">
                                <i class="fas fa-users-cog"></i>
                            </div>
                            <div>
                                <h5 style="font-size: 16px; margin-bottom: 5px; font-weight: 600; color: var(--medium);">Reduzir permissões excessivas em grupos</h5>
                                <p style="font-size: 14px; color: var(--text-secondary); margin: 0;">$($AnalysisData.ExcessivePermissions.Count) grupos possuem permissões de controle total desnecessárias. Aplique o princípio do menor privilégio.</p>
                            </div>
                        </div>
                        
                        <!-- Insight 3: Baixa Prioridade -->
                        <div style="display: flex; gap: 15px; padding: 16px; margin-bottom: 16px; border-radius: 8px; background-color: rgba(56, 161, 105, 0.05); border-left: 4px solid var(--low); box-shadow: var(--shadow-sm);">
                            <div style="min-width: 36px; min-height: 36px; border-radius: 50%; background-color: rgba(56, 161, 105, 0.1); color: var(--low); display: flex; align-items: center; justify-content: center;">
                                <i class="fas fa-sitemap"></i>
                            </div>
                            <div>
                                <h5 style="font-size: 16px; margin-bottom: 5px; font-weight: 600; color: var(--low);">Simplificar estrutura de permissões</h5>
                                <p style="font-size: 14px; color: var(--text-secondary); margin: 0;">Existem $($AnalysisData.InheritanceBroken.Count) pastas com quebra de herança que podem ser simplificadas para melhorar a gestão e visibilidade.</p>
                            </div>
                        </div>
                        
                        <!-- Insight 4: Informativo -->
                        <div style="display: flex; gap: 15px; padding: 16px; margin-bottom: 16px; border-radius: 8px; background-color: rgba(0, 120, 212, 0.05); border-left: 4px solid var(--primary); box-shadow: var(--shadow-sm);">
                            <div style="min-width: 36px; min-height: 36px; border-radius: 50%; background-color: rgba(0, 120, 212, 0.1); color: var(--primary); display: flex; align-items: center; justify-content: center;">
                                <i class="fas fa-project-diagram"></i>
                            </div>
                            <div>
                                <h5 style="font-size: 16px; margin-bottom: 5px; font-weight: 600; color: var(--primary);">Implementar modelo AGDLP para permissões</h5>
                                <p style="font-size: 14px; color: var(--text-secondary); margin: 0;">Adote o modelo AGDLP (Account, Global, Domain Local, Permission) para organizar permissões de forma hierárquica e gerenciável.</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Todos os Problemas -->
        <div class="table-section">
            <div class="table-header">
                <div>
                    <h3 class="table-title"><i class="fas fa-exclamation-triangle"></i> Todos os Problemas</h3>
                    <p class="table-subtitle">Lista completa de problemas de segurança detectados</p>
                </div>
            </div>
            
            <!-- Filtros -->
            <div class="filter-section">
                <div class="filter-field">
                    <label class="filter-label">Severidade</label>
                    <select class="filter-select" id="severityFilter">
                        <option value="">Todas</option>
                        <option value="Alta">Alta</option>
                        <option value="Média">Média</option>
                        <option value="Baixa">Baixa</option>
                    </select>
                </div>
                
                <div class="filter-field">
                    <label class="filter-label">Tipo</label>
                    <select class="filter-select" id="typeFilter">
                        <option value="">Todos</option>
                        <option value="Usuário direto">Usuário direto</option>
                        <option value="Grupos com permissões de risco">Grupos com permissões de risco</option>
                        <option value="Quebra de herança desnecessária">Quebra de herança desnecessária</option>
                    </select>
                </div>
                
                <div class="filter-field">
                    <label class="filter-label">Pasta</label>
                    <select class="filter-select" id="folderFilter">
                        <option value="">Todas</option>
                        <!-- Preenchido dinamicamente via JavaScript -->
                    </select>
                </div>
                
                <div class="filter-field">
                    <label class="filter-label">Entidade</label>
                    <select class="filter-select" id="entityFilter">
                        <option value="">Todas</option>
                        <!-- Preenchido dinamicamente via JavaScript -->
                    </select>
                </div>
                
                <div class="filter-field">
                    <label class="filter-label">Permissão</label>
                    <select class="filter-select" id="permissionFilter">
                        <option value="">Todas</option>
                        <!-- Preenchido dinamicamente via JavaScript -->
                    </select>
                </div>
            </div>
            
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 0 1.5rem; margin-bottom: 0.5rem; border-bottom: 1px solid #e9ecef; padding-bottom: 0.5rem;">
                <div style="display: flex; gap: 15px;">
                    <button class="filter-apply" id="applyFilters">
                        <i class="fas fa-filter"></i> Aplicar Filtros
                    </button>
                    <button class="filter-clear" id="resetFilters">
                        <i class="fas fa-undo"></i> Limpar
                    </button>
                </div>
                <div style="display: flex; align-items: center; gap: 15px;">
                    <div class="entries-per-page" style="white-space: nowrap; display: flex; align-items: center; gap: 8px;">
                        <label>Mostrar</label>
                        <select class="entries-select" id="entriesPerPage">
                            <option value="10">10</option>
                            <option value="25">25</option>
                            <option value="50">50</option>
                            <option value="100">100</option>
                        </select>
                        <span>registros</span>
                    </div>
                    <div class="table-search">
                        <i class="fas fa-search table-search-icon"></i>
                        <input type="text" id="searchInput" placeholder="Buscar problemas..." class="table-search-input">
                    </div>
                </div>
            </div>
            
            <div class="table-body">
                <table class="security-table" id="problemsTable">
                    <thead>
                        <tr>
                            <th>Severidade</th>
                            <th>Tipo</th>
                            <th>Pasta</th>
                            <th>Entidade</th>
                            <th>Permissão</th>
                            <th>Recomendação</th>
                        </tr>
                    </thead>
                    <tbody id="tableBody">
                        <!-- Será preenchido via JavaScript -->
                    </tbody>
                </table>
            </div>
            
            <div class="pagination-container">
                <div class="pagination-info" id="tableInfo">
                    <!-- Será atualizado via JavaScript -->
                </div>
                <div class="pagination" id="pagination">
                    <!-- Paginação será preenchida via JavaScript -->
                </div>
            </div>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p><span class="dashboard-title">Security Permissions Dashboard</span> | Gerado em $currentDate | Desenvolvido por Mathews Buzetti</p>
        </div>
    </div>

    <script>
        // Dados de problemas em formato JSON
        const allProblems = [
"@

    # CORREÇÃO: Converter todos os problemas para JSON com formato correto
    $problemsJson = @()
    
    # Verificar se existem problemas para análise
    if ($AnalysisData.AllProblems -and $AnalysisData.AllProblems.Count -gt 0) {
        foreach ($problem in $AnalysisData.AllProblems) {
            # CORREÇÃO: Escapar corretamente caracteres especiais para JSON
            $folderPath = $problem.FolderPath -replace '\\', '\\\\'
            $folderPath = $folderPath -replace '"', '\\"'
            
            $identity = $problem.Identity -replace '\\', '\\\\'
            $identity = $identity -replace '"', '\\"'
            
            $permission = $problem.Permission -replace '"', '\\"'
            $recommendation = $problem.Recommendation -replace '"', '\\"'
            
            # CORREÇÃO: Usar formato JSON válido com aspas duplas
            $problemJson = "{`"severity`":`"$($problem.Severity)`",`"type`":`"$($problem.Type)`",`"folderPath`":`"$folderPath`",`"identity`":`"$identity`",`"permission`":`"$permission`",`"recommendation`":`"$recommendation`",`"hasFullControl`":$(if ($problem.HasFullControl) { "true" } else { "false" })}"
            $problemsJson += $problemJson
        }
    } else {
        # Adicionar problema de exemplo para testar a visualização
        $problemsJson += "{`"severity`":`"Alta`",`"type`":`"Usuário direto`",`"folderPath`":`"\\\\Exemplo\\Pasta`",`"identity`":`"DOMAIN\\\\usuario`",`"permission`":`"FullControl`",`"recommendation`":`"Substituir por permissão de grupo`",`"hasFullControl`":true}"
    }
    
    # Adicionar ao HTML com formato correto
    $html += $problemsJson -join ",`n"
    
    $html += @"
        ];

        // Variáveis para paginação e filtros
        let currentPage = 1;
        let entriesPerPage = 10;
        let filteredProblems = [...allProblems];
        
        // Função para popular os filtros dinâmicos
        function populateFilters() {
            console.log("Populando filtros com " + allProblems.length + " problemas");
            // Obter valores únicos para cada filtro
            const folderSet = new Set();
            const entitySet = new Set();
            const permissionSet = new Set();
            
            allProblems.forEach(problem => {
                folderSet.add(problem.folderPath);
                entitySet.add(problem.identity);
                permissionSet.add(problem.permission);
            });
            
            // Preencher o dropdown de pastas
            const folderFilter = document.getElementById('folderFilter');
            folderFilter.innerHTML = '<option value="">Todas</option>';
            folderSet.forEach(folder => {
                const option = document.createElement('option');
                option.value = folder;
                option.textContent = folder.replace(/\\\\/g, '\\');
                folderFilter.appendChild(option);
            });
            
            // Preencher o dropdown de entidades
            const entityFilter = document.getElementById('entityFilter');
            entityFilter.innerHTML = '<option value="">Todas</option>';
            entitySet.forEach(entity => {
                const option = document.createElement('option');
                option.value = entity;
                option.textContent = entity.replace(/\\\\/g, '\\');
                entityFilter.appendChild(option);
            });
            
            // Preencher o dropdown de permissões
            const permissionFilter = document.getElementById('permissionFilter');
            permissionFilter.innerHTML = '<option value="">Todas</option>';
            permissionSet.forEach(permission => {
                const option = document.createElement('option');
                option.value = permission;
                option.textContent = permission;
                permissionFilter.appendChild(option);
            });
        }

        // Função para aplicar filtros
        function applyFilters() {
            const severityValue = document.getElementById('severityFilter').value;
            const typeValue = document.getElementById('typeFilter').value;
            const folderValue = document.getElementById('folderFilter').value;
            const entityValue = document.getElementById('entityFilter').value;
            const permissionValue = document.getElementById('permissionFilter').value;
            
            filteredProblems = allProblems.filter(problem => {
                return (!severityValue || problem.severity === severityValue) &&
                       (!typeValue || problem.type === typeValue) &&
                       (!folderValue || problem.folderPath === folderValue) &&
                       (!entityValue || problem.identity === entityValue) &&
                       (!permissionValue || problem.permission === permissionValue);
            });
            
            currentPage = 1;
            displayProblems();
        }

        // Função para resetar filtros
        function resetFilters() {
            document.getElementById('severityFilter').value = '';
            document.getElementById('typeFilter').value = '';
            document.getElementById('folderFilter').value = '';
            document.getElementById('entityFilter').value = '';
            document.getElementById('permissionFilter').value = '';
            
            filteredProblems = [...allProblems];
            currentPage = 1;
            displayProblems();
        }

        // Função de busca na tabela
        function searchProblems() {
            const input = document.getElementById('searchInput');
            const filter = input.value.toUpperCase();
            
            filteredProblems = allProblems.filter(problem => {
                return Object.values(problem).some(value => 
                    value && value.toString().toUpperCase().includes(filter)
                );
            });
            
            currentPage = 1;
            displayProblems();
        }
        
        // Função para atualizar a quantidade de registros por página
        function updateEntriesPerPage() {
            entriesPerPage = parseInt(document.getElementById('entriesPerPage').value);
            currentPage = 1;
            displayProblems();
        }
        
        // Função para criar ícones
        function createIcon(iconClass) {
            const icon = document.createElement('i');
            icon.className = iconClass;
            return icon;
        }
        
        // Função para renderizar a tabela
        function displayProblems() {
            const tableBody = document.getElementById('tableBody');
            if (!tableBody) {
                console.error("Elemento 'tableBody' não encontrado");
                return;
            }
            
            console.log("Exibindo problemas na tabela. Total filtrado:", filteredProblems.length);
            
            // Limpar a tabela existente
            tableBody.innerHTML = '';
            
            // Se não tiver problemas, mostrar mensagem
            if (filteredProblems.length === 0) {
                const row = document.createElement('tr');
                const td = document.createElement('td');
                td.colSpan = 6;
                td.textContent = 'Nenhum problema encontrado.';
                td.style.textAlign = 'center';
                td.style.padding = '20px';
                row.appendChild(td);
                tableBody.appendChild(row);
                
                updateTableInfo(0, 0);
                renderPagination();
                return;
            }
            
            // Calcular índices para paginação
            const startIndex = (currentPage - 1) * entriesPerPage;
            const endIndex = Math.min(startIndex + entriesPerPage, filteredProblems.length);
            
            // Adicionar linhas à tabela
            for (let i = startIndex; i < endIndex; i++) {
                if (i >= filteredProblems.length) break;
                
                const problem = filteredProblems[i];
                const row = document.createElement('tr');
                
                // Configurações de badges baseadas no tipo e severidade
                let badgeClass = "badge-high";
                if (problem.severity === "Média") badgeClass = "badge-medium";
                if (problem.severity === "Baixa") badgeClass = "badge-low";
                
                // Determinar tipo de problema e ícone
                let typeClass, typeIconClass;
                
                if (problem.type === "Usuário direto") {
                    typeClass = "badge-loose-user";
                    typeIconClass = "fas fa-user";
                } else if (problem.type === "Grupos com permissões de risco") {
                    typeClass = "badge-excessive";
                    typeIconClass = "fas fa-exclamation-triangle";
                } else if (problem.type === "Quebra de herança desnecessária") {
                    typeClass = "badge-inheritance";
                    typeIconClass = "fas fa-unlink";
                } else {
                    typeClass = "badge-loose-user";
                    typeIconClass = "fas fa-exclamation-circle";
                }
                
                // Severidade
                const sevTd = document.createElement('td');
                const sevSpan = document.createElement('span');
                sevSpan.className = 'severity-badge ' + badgeClass;
                sevSpan.appendChild(createIcon('fas fa-exclamation-circle'));
                sevSpan.appendChild(document.createTextNode(' ' + problem.severity));
                sevTd.appendChild(sevSpan);
                // Tipo
                const typeTd = document.createElement('td');
                const typeSpan = document.createElement('span');
                
                // Aplicar o badge apropriado ao tipo de problema
                typeSpan.className = 'problem-badge ' + typeClass;
                typeSpan.appendChild(createIcon(typeIconClass));
                typeSpan.appendChild(document.createTextNode(' ' + problem.type));
                
                typeTd.appendChild(typeSpan);
                
                // Demais colunas
                const folderTd = document.createElement('td');
                // Correção para exibir corretamente caminhos com barras invertidas
                folderTd.textContent = problem.folderPath.replace(/\\\\/g, '\\');
                
                const entityTd = document.createElement('td');
                // Correção para exibir corretamente entidades com barras invertidas
                entityTd.textContent = problem.identity.replace(/\\\\/g, '\\');
                
                const permTd = document.createElement('td');
                // Destacar FullControl com estilo de problema excessivo
                if (problem.permission.includes("FullControl")) {
                    const permSpan = document.createElement('span');
                    permSpan.className = 'problem-badge badge-high';
                    permSpan.style.padding = '3px 8px'; // Ajuste de tamanho do badge
                    permSpan.style.fontSize = '11px';   // Ajuste de fonte do badge
                    permSpan.appendChild(createIcon('fas fa-exclamation-circle'));
                    permSpan.appendChild(document.createTextNode(' FullControl'));
                    
                    // Substituir "FullControl" pelo badge, mantendo o resto do texto
                    const restOfPermission = problem.permission.replace("FullControl", "").trim();
                    if (restOfPermission) {
                        permTd.textContent = restOfPermission + " ";
                        permTd.appendChild(permSpan);
                    } else {
                        permTd.appendChild(permSpan);
                    }
                } else {
                    permTd.textContent = problem.permission;
                }
                const recTd = document.createElement('td');
                recTd.textContent = problem.recommendation;
                
                // Adicionar todos os TDs à linha
                row.appendChild(sevTd);
                row.appendChild(typeTd);
                row.appendChild(folderTd);
                row.appendChild(entityTd);
                row.appendChild(permTd);
                row.appendChild(recTd);
                
                tableBody.appendChild(row);
            }
            
            // Atualizar informações da tabela
            updateTableInfo(startIndex, endIndex);
            
            // Renderizar paginação
            renderPagination();
        }
        
        // Função para atualizar a informação da tabela
        function updateTableInfo(startIndex, endIndex) {
            const tableInfo = document.getElementById('tableInfo');
            if (!tableInfo) return;
            
            if (filteredProblems.length === 0) {
                tableInfo.textContent = "Nenhum registro encontrado";
            } else {
                tableInfo.textContent = "Mostrando " + (startIndex + 1) + " a " + endIndex + " de " + filteredProblems.length + " registros";
            }
        }
        
        // Função para renderizar a paginação
        function renderPagination() {
            const paginationElement = document.getElementById('pagination');
            if (!paginationElement) {
                console.error("Elemento 'pagination' não encontrado");
                return;
            }
            
            // Limpar paginação existente
            paginationElement.innerHTML = '';
            
            if (filteredProblems.length === 0) return;
            
            const totalPages = Math.ceil(filteredProblems.length / entriesPerPage);
            
            // Botão "Anterior"
            const prevButton = document.createElement('button');
            prevButton.className = 'pagination-button ' + (currentPage === 1 ? 'disabled' : '');
            prevButton.appendChild(createIcon('fas fa-chevron-left'));
            
            prevButton.addEventListener('click', () => {
                if (currentPage > 1) {
                    currentPage--;
                    displayProblems();
                }
            });
            paginationElement.appendChild(prevButton);
            
            // Determinar quais páginas mostrar
            let startPage = Math.max(1, currentPage - 2);
            let endPage = Math.min(totalPages, startPage + 4);
            
            if (endPage - startPage < 4 && startPage > 1) {
                startPage = Math.max(1, endPage - 4);
            }
            
            // Primeira página e elipses
            if (startPage > 1) {
                const firstPageButton = document.createElement('button');
                firstPageButton.className = 'pagination-button';
                firstPageButton.textContent = '1';
                firstPageButton.addEventListener('click', () => {
                    currentPage = 1;
                    displayProblems();
                });
                paginationElement.appendChild(firstPageButton);
                
                if (startPage > 2) {
                    const ellipsis = document.createElement('span');
                    ellipsis.className = 'pagination-button disabled';
                    ellipsis.textContent = '...';
                    paginationElement.appendChild(ellipsis);
                }
            }
            
            // Páginas numeradas
            for (let i = startPage; i <= endPage; i++) {
                const pageButton = document.createElement('button');
                pageButton.className = 'pagination-button ' + (i === currentPage ? 'active' : '');
                pageButton.textContent = i;
                pageButton.addEventListener('click', () => {
                    currentPage = i;
                    displayProblems();
                });
                paginationElement.appendChild(pageButton);
            }
            
            // Última página e elipses
            if (endPage < totalPages) {
                if (endPage < totalPages - 1) {
                    const ellipsis = document.createElement('span');
                    ellipsis.className = 'pagination-button disabled';
                    ellipsis.textContent = '...';
                    paginationElement.appendChild(ellipsis);
                }
                
                const lastPageButton = document.createElement('button');
                lastPageButton.className = 'pagination-button';
                lastPageButton.textContent = totalPages;
                lastPageButton.addEventListener('click', () => {
                    currentPage = totalPages;
                    displayProblems();
                });
                paginationElement.appendChild(lastPageButton);
            }
            
            // Botão "Próximo"
            const nextButton = document.createElement('button');
            nextButton.className = 'pagination-button ' + (currentPage === totalPages ? 'disabled' : '');
            nextButton.appendChild(createIcon('fas fa-chevron-right'));
            
            nextButton.addEventListener('click', () => {
                if (currentPage < totalPages) {
                    currentPage++;
                    displayProblems();
                }
            });
            paginationElement.appendChild(nextButton);
        }
        
        // Carregar dados na inicialização
        document.addEventListener('DOMContentLoaded', function() {
            console.log("Documento carregado. Inicializando dashboard...");
            console.log("Total de problemas carregados:", allProblems.length);
            
            // Preencher filtros dinâmicos
            populateFilters();
            
            // Inicializar a tabela
            displayProblems();
            
            // Configurar event listeners
            document.getElementById('searchInput').addEventListener('keyup', searchProblems);
            document.getElementById('applyFilters').addEventListener('click', applyFilters);
            document.getElementById('resetFilters').addEventListener('click', resetFilters);
            document.getElementById('entriesPerPage').addEventListener('change', updateEntriesPerPage);
        });
    </script>
</body>
</html>
"@

    # Salvar o HTML em um arquivo
    $html | Out-File -FilePath $HtmlReport -Encoding utf8
    Write-Log -Message "Relatório HTML moderno gerado em $HtmlReport"
    
    return $HtmlReport
}


# Escaneamento principal
Show-Header

Write-Host ""
Write-Host " [!] " -NoNewline -ForegroundColor Red
Write-Host "INICIANDO SISTEMA DE ESCANEAMENTO AVANÇADO" -ForegroundColor Cyan
Write-Host " [+] " -NoNewline -ForegroundColor Green
Write-Host "ALVO: " -NoNewline -ForegroundColor DarkCyan
Write-Host "$ServerIP" -ForegroundColor Green
Write-Host " [+] " -NoNewline -ForegroundColor Green
Write-Host "DESTINO: " -NoNewline -ForegroundColor DarkCyan
Write-Host "$OutputPath" -ForegroundColor Green
Write-Host " [+] " -NoNewline -ForegroundColor Green
Write-Host "PROFUNDIDADE MÁXIMA: " -NoNewline -ForegroundColor DarkCyan
Write-Host "$MaxDepth níveis" -ForegroundColor Green
Write-Host " [+] " -NoNewline -ForegroundColor Green
Write-Host "COMPARTILHAMENTOS: " -NoNewline -ForegroundColor DarkCyan
Write-Host "$($NetworkShares.Count)" -ForegroundColor Green

Write-Log -Message "Iniciando escaneamento de $($NetworkShares.Count) compartilhamentos com profundidade máxima de $MaxDepth"

# Inicializar arquivo CSV global
$global:HeaderWritten = $false

# Analisar cada compartilhamento e salvar em um único CSV
$shareIndex = 0
foreach ($sharePath in $NetworkShares) {
    $shareIndex++
    $shareName = ($sharePath -split '\\')[-1]
    
    Write-Host ""
    Write-Host "┌─────────────────────────────────────────────────────────┐" -ForegroundColor White
    Write-Host "│ ESCANEANDO COMPARTILHAMENTO $shareIndex/$($NetworkShares.Count): " -NoNewline -ForegroundColor Yellow
    Write-Host "$shareName" -NoNewline -ForegroundColor Green
    Write-Host "                   │" -ForegroundColor Yellow
    Write-Host "└─────────────────────────────────────────────────────────┘" -ForegroundColor White
    
    Write-Log -Message "Iniciando escaneamento de $sharePath"
    
    try {
        # Etapa 1: Contagem de pastas para estimativa de progresso
        Write-Host " [ETAPA 1] " -NoNewline -ForegroundColor Yellow
        Write-Host "CONTANDO PASTAS" -ForegroundColor White
        
        # Resetar contadores para este compartilhamento
        $global:TotalFolders = 0
        $global:ProcessedFolders = 0
        $global:TotalPermissions = 0
        $global:BatchCounter = 0
        
        # Iniciar contagem com progresso indeterminado
        Write-Progress -Activity "Contando pastas" -Status "Analisando estrutura de diretórios" -Id 1
        
        # Contar pastas com limite de profundidade
        $countingTimer = [System.Diagnostics.Stopwatch]::StartNew()
        Get-FoldersRecursively -Path $sharePath -MaximumDepth $MaxDepth | Out-Null
        $countingTimer.Stop()
        
        # Finalizar progresso de contagem
        Write-Progress -Activity "Contando pastas" -Completed -Id 1
        
        # Exibir resultado da contagem
        $countTime = if ($countingTimer.ElapsedMilliseconds -lt 1000) { 
            "$($countingTimer.ElapsedMilliseconds)ms" 
        } else { 
            "$([math]::Round($countingTimer.ElapsedMilliseconds/1000, 1))s" 
        }
        
        Write-Host ""
        Write-Host " [RESULTADO] " -NoNewline -ForegroundColor Green
        Write-Host "Encontradas " -NoNewline -ForegroundColor White 
        if ($global:TotalFolders -eq 0) {
            Write-Host "NENHUMA PASTA" -NoNewline -ForegroundColor Yellow
        } else {
            Write-Host "$global:TotalFolders pastas" -NoNewline -ForegroundColor Yellow
        }
        Write-Host " ($countTime)" -ForegroundColor White
        Write-Log -Message "Encontradas $global:TotalFolders pastas em $sharePath"
        
        # Etapa 2: Processamento de permissões em lotes
        Write-Host ""
        Write-Host " [ETAPA 2] " -NoNewline -ForegroundColor Yellow
        Write-Host "ESCANEANDO PERMISSÕES" -ForegroundColor White
        
        # Reinicializar contadores de processamento
        $global:ProcessedFolders = 0
        $global:StartTime = Get-Date
        
        # Obter lista de pastas para processamento
        $allFolders = @()
        $allFolders += Get-FoldersRecursively -Path $sharePath -MaximumDepth $MaxDepth
        
        # Adicionar o compartilhamento raiz
        $shareFolder = Get-Item -Path $sharePath -ErrorAction SilentlyContinue
        if ($shareFolder) {
            $allFolders = @($shareFolder) + $allFolders
            $global:TotalFolders++
        }
        
        # Processar em lotes para melhor performance e uso de memória
        $currentBatch = @()
        $batchCount = 0
        
        foreach ($folder in $allFolders) {
            $currentBatch += $folder
            $batchCount++
            
            if ($batchCount -ge $BatchSize) {
                Process-FolderBatch -Folders $currentBatch -OutputFile $OutFileCsv
                $currentBatch = @()
                $batchCount = 0
            }
        }
        
        # Processar o último lote restante
        if ($currentBatch.Count -gt 0) {
            Process-FolderBatch -Folders $currentBatch -OutputFile $OutFileCsv
        }
        
        # Completar a barra de progresso
        Write-Progress -Activity "Escaneando permissões" -Completed
        
        # Atualizar contadores totais
        $global:TotalFoldersAll += $global:TotalFolders
        $global:TotalPermissionsAll += $global:TotalPermissions
        $global:ErrorCountAll += $global:ErrorCount
        
        # Exibir resumo deste compartilhamento
        Write-Host ""
        Write-Host " [CONCLUÍDO] " -NoNewline -ForegroundColor Green
        Write-Host "Compartilhamento: " -NoNewline -ForegroundColor White
        Write-Host "$shareName" -ForegroundColor Yellow
        Write-Host "            Total de pastas: " -NoNewline -ForegroundColor White 
        Write-Host "$global:TotalFolders" -ForegroundColor Yellow
        Write-Host "            Total de permissões: " -NoNewline -ForegroundColor White
        Write-Host "$global:TotalPermissions" -ForegroundColor Yellow
        Write-Log -Message "Compartilhamento $sharePath processado com sucesso. Total de permissões: $global:TotalPermissions"
    }
    catch {
        Write-Host " [FALHA] " -NoNewline -ForegroundColor Red
        Write-Host "Erro processando compartilhamento $sharePath - $($_.Exception.Message)" -ForegroundColor Red
        Write-Log -Message "Erro processando compartilhamento $sharePath - $($_.Exception.Message)" -Type "ERROR"
    }
}

# Gerar relatório HTML se solicitado
if ($GenerateHTML) {
    $analysisData = Analyze-Permissions -CsvPath $OutFileCsv
    $htmlPath = Generate-HTMLReport -AnalysisData $analysisData
}

# Exibir resumo final
$totalElapsedTime = (Get-Date) - $global:StartTime
$elapsedTimeStr = "{0:hh\:mm\:ss}" -f $totalElapsedTime

Write-Host ""
Write-Host "┌─────────────────────────────────────────────────────────┐" -ForegroundColor White
Write-Host "│                    " -NoNewline -ForegroundColor Green
Write-Host "ESCANEAMENTO CONCLUÍDO" -NoNewline -ForegroundColor Green
Write-Host "               │" -ForegroundColor Green
Write-Host "└─────────────────────────────────────────────────────────┘" -ForegroundColor White
Write-Host ""
Write-Host " ✓ " -NoNewline -ForegroundColor Green
Write-Host "Duração total: " -NoNewline -ForegroundColor White
Write-Host "$elapsedTimeStr" -ForegroundColor Yellow
Write-Host " ✓ " -NoNewline -ForegroundColor Green
Write-Host "Pastas processadas: " -NoNewline -ForegroundColor White
Write-Host "$global:TotalFoldersAll" -ForegroundColor Yellow
Write-Host " ✓ " -NoNewline -ForegroundColor Green
Write-Host "Permissões encontradas: " -NoNewline -ForegroundColor White
Write-Host "$global:TotalPermissionsAll" -ForegroundColor Yellow
Write-Host " ✓ " -NoNewline -ForegroundColor Green
Write-Host "Arquivo CSV unificado: " -NoNewline -ForegroundColor White
Write-Host "$OutFileCsv" -ForegroundColor Yellow
if ($GenerateHTML) {
    Write-Host " ✓ " -NoNewline -ForegroundColor Green
    Write-Host "Dashboard HTML moderno salvo em: " -NoNewline -ForegroundColor White
    Write-Host "$htmlPath" -ForegroundColor Yellow
    
    # Abrir o relatório HTML automaticamente
    Start-Process $htmlPath
}
Write-Host " ✓ " -NoNewline -ForegroundColor Green
Write-Host "Log do processo: " -NoNewline -ForegroundColor White
Write-Host "$LogFile" -ForegroundColor Yellow
Write-Log -Message "Escaneamento completo. Duração total: $elapsedTimeStr"
