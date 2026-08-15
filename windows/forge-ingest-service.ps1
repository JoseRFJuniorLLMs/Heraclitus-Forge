<#
.SYNOPSIS
    Instala, opera e remove o ingestor do Forge como servico do Windows.

.DESCRIPTION
    O `ingest.exe` sabe falar com o SCM (subcomando `service`). Este script
    regista-o, aponta-lhe a fonte pela configuracao de maquina, aplica ACLs de
    menor privilegio e liga a recuperacao automatica.

    Sem isto o ingestor e um CLI que alguem tem de correr a mao -- e um ingestor
    que so corre quando alguem se lembra nao e um ingestor.

.EXAMPLE
    .\forge-ingest-service.ps1 install `
        -Source C:\logs\nginx\access.log `
        -Artifact D:\DEV\Heraclitus-Forge\registry\nginx_access

.EXAMPLE
    .\forge-ingest-service.ps1 status
    .\forge-ingest-service.ps1 logs
    .\forge-ingest-service.ps1 uninstall
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateSet('install', 'uninstall', 'start', 'stop', 'status', 'logs')]
    [string]$Action,

    [string]$Source,
    [string]$Artifact,
    [string]$DataDir = 'D:\HeraclitusForge\data',
    [string]$LogDir  = "$env:ProgramData\HeraclitusForge\logs",
    [string]$Exe,
    [string]$ServiceName = 'HeraclitusForgeIngest'
)

$ErrorActionPreference = 'Stop'
$account = "NT SERVICE\$ServiceName"

# $PSScriptRoot nao esta disponivel dentro do bloco param() em PS 5.1, e o
# CARGO_TARGET_DIR pode redirecionar o build para fora da arvore do projeto.
# Resolver aqui, procurando nos dois sitios plausiveis.
if (-not $Exe) {
    $raiz = Split-Path -Parent $PSCommandPath
    # Sem operador ?? -- o PowerShell 5.1 nao o tem.
    $target = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { 'D:\cargo-target' }
    # Escolhe o MAIS RECENTE, nao o primeiro da lista. Quando o CARGO_TARGET_DIR
    # passou a existir, o build mudou de sitio e o `rust\target\release` ficou
    # com um binario obsoleto -- que continua a existir e a parecer valido. Um
    # servico registado sobre esse exe antigo instala-se sem erro e depois
    # recusa-se a arrancar, porque lhe falta o subcomando `service`.
    $candidatos = @(
        (Join-Path $raiz '..\rust\target\release\ingest.exe'),
        (Join-Path $target 'release\ingest.exe')
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } |
        ForEach-Object { Get-Item -LiteralPath $_ } |
        Sort-Object LastWriteTime -Descending
    if (-not $candidatos) {
        throw "ingest.exe nao encontrado; compile com ``cargo build --release --bin ingest`` ou passe -Exe"
    }
    $Exe = $candidatos[0].FullName
    if ($candidatos.Count -gt 1) {
        Write-Host "  (encontrados $($candidatos.Count) binarios; usado o mais recente: $Exe)" -ForegroundColor DarkGray
    }
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]$id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Admin {
    if (-not (Test-Admin)) {
        throw "esta accao exige uma consola de administrador"
    }
}

function Set-MachineEnv([string]$Name, [AllowNull()][string]$Value) {
    [Environment]::SetEnvironmentVariable($Name, $Value, 'Machine')
}

$envNames = @(
    'FORGE_INGEST_SOURCE', 'FORGE_INGEST_ARTIFACT', 'FORGE_INGEST_DB',
    'FORGE_INGEST_QUARANTINE', 'FORGE_INGEST_LOGDIR', 'FORGE_QUARANTINE_KEY'
)

switch ($Action) {

'install' {
    Assert-Admin
    if (-not $Source)   { throw '-Source e obrigatorio (o ficheiro de log a seguir)' }
    if (-not $Artifact) { throw '-Artifact e obrigatorio (pasta do conector no registry)' }
    if (-not (Test-Path -LiteralPath $Source)) { throw "fonte nao existe: $Source" }
    if (-not (Test-Path -LiteralPath $Artifact -PathType Container)) {
        throw "artefato nao existe: $Artifact"
    }
    $exeFull = (Resolve-Path -LiteralPath $Exe).Path
    $dataFull = [IO.Path]::GetFullPath($DataDir)
    $logFull  = [IO.Path]::GetFullPath($LogDir)
    New-Item -ItemType Directory -Path $dataFull, $logFull -Force | Out-Null

    # A chave da quarentena e um SEGREDO: nao pode nascer de um argumento que
    # fica no historico da consola. Gera-se aqui, uma vez, se ainda nao existir.
    $chave = [Environment]::GetEnvironmentVariable('FORGE_QUARANTINE_KEY', 'Machine')
    if (-not $chave -or $chave.Length -ne 64) {
        # RandomNumberGenerator::Fill e .NET Core; o PS 5.1 corre em .NET
        # Framework, onde o CSPRNG e o RNGCryptoServiceProvider.
        $bytes = New-Object byte[] 32
        $rng = [Security.Cryptography.RNGCryptoServiceProvider]::new()
        try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
        $chave = -join ($bytes | ForEach-Object { $_.ToString('x2') })
        Write-Host "FORGE_QUARANTINE_KEY gerada (32 bytes). Guarde-a em custodia:" -ForegroundColor Yellow
        Write-Host "  $chave" -ForegroundColor Yellow
        Write-Host "  Sem ela a quarentena fica ilegivel para sempre." -ForegroundColor Yellow
    }

    Set-MachineEnv 'FORGE_INGEST_SOURCE'     $Source
    Set-MachineEnv 'FORGE_INGEST_ARTIFACT'   $Artifact
    Set-MachineEnv 'FORGE_INGEST_DB'         (Join-Path $dataFull 'ingest.hdb')
    Set-MachineEnv 'FORGE_INGEST_QUARANTINE' (Join-Path $dataFull 'quarantine.hq')
    Set-MachineEnv 'FORGE_INGEST_LOGDIR'     $logFull
    Set-MachineEnv 'FORGE_QUARANTINE_KEY'    $chave

    $existente = Get-Service $ServiceName -ErrorAction SilentlyContinue
    if ($existente) {
        if ($existente.Status -eq 'Running') {
            Stop-Service $ServiceName -Force
            $existente.WaitForStatus('Stopped', '00:00:30')
        }
        & sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Milliseconds 800
    }

    # `service` e o subcomando que faz o exe entrar no dispatcher do SCM.
    & sc.exe create $ServiceName binPath= "`"$exeFull`" service" start= auto `
        DisplayName= "Heraclitus Forge - Ingestor" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'sc create falhou' }
    & sc.exe description $ServiceName `
        "Segue um ficheiro de log, produz Fatos Operacionais e persiste-os no FactStore." | Out-Null

    # Conta virtual de menor privilegio, como o HeraclitusDB.
    & sc.exe config $ServiceName obj= $account | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'nao foi possivel aplicar a conta virtual' }

    # Recuperacao: um ingestor morto nao da erro nenhum -- so deixa de haver
    # Fatos, e isso e invisivel ate alguem procurar.
    & sc.exe failure $ServiceName reset= 86400 `
        actions= restart/5000/restart/15000/restart/60000 | Out-Null

    # ACLs: o servico le a fonte e escreve no data/logs. Nada mais.
    & icacls.exe $dataFull '/grant' "$account`:(OI)(CI)M" '/T' '/C' | Out-Null
    & icacls.exe $logFull  '/grant' "$account`:(OI)(CI)M" '/T' '/C' | Out-Null
    & icacls.exe (Split-Path $exeFull) '/grant' "$account`:(OI)(CI)RX" | Out-Null
    & icacls.exe $Source '/grant' "$account`:(R)" | Out-Null
    & icacls.exe $Artifact '/grant' "$account`:(OI)(CI)RX" '/T' '/C' | Out-Null

    Start-Service $ServiceName
    (Get-Service $ServiceName).WaitForStatus('Running', '00:00:30')
    Write-Host "INSTALADO  $ServiceName  ->  $Source" -ForegroundColor Green
    Write-Host "  logs: $logFull\forge-ingest.log" -ForegroundColor DarkGray
}

'uninstall' {
    Assert-Admin
    $svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) { Write-Host "nao instalado"; break }
    if ($svc.Status -eq 'Running') {
        Stop-Service $ServiceName -Force
        $svc.WaitForStatus('Stopped', '00:00:30')
    }
    & sc.exe delete $ServiceName | Out-Null
    foreach ($n in $envNames) { Set-MachineEnv $n $null }
    Write-Host "REMOVIDO $ServiceName (variaveis de maquina limpas)" -ForegroundColor Green
    Write-Host "  os dados em $DataDir NAO foram tocados" -ForegroundColor DarkGray
}

'start' { Assert-Admin; Start-Service $ServiceName; (Get-Service $ServiceName).Status }
'stop'  { Assert-Admin; Stop-Service $ServiceName -Force; (Get-Service $ServiceName).Status }

'status' {
    $svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) { Write-Host "nao instalado"; break }
    $info = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    [pscustomobject]@{
        Estado     = $svc.Status
        Conta      = $info.StartName
        Arranque   = $info.StartMode
        Binario    = $info.PathName
        Fonte      = [Environment]::GetEnvironmentVariable('FORGE_INGEST_SOURCE', 'Machine')
        Artefato   = [Environment]::GetEnvironmentVariable('FORGE_INGEST_ARTIFACT', 'Machine')
        Destino    = [Environment]::GetEnvironmentVariable('FORGE_INGEST_DB', 'Machine')
        ChaveQuar  = if ([Environment]::GetEnvironmentVariable('FORGE_QUARANTINE_KEY','Machine')) { 'definida' } else { 'EM FALTA' }
    } | Format-List
    & sc.exe qfailure $ServiceName | Select-String 'RESET_PERIOD|RESTART'
}

'logs' {
    $dir = [Environment]::GetEnvironmentVariable('FORGE_INGEST_LOGDIR', 'Machine')
    if (-not $dir) { $dir = $LogDir }
    $ficheiro = Get-ChildItem -LiteralPath $dir -Filter 'forge-ingest.log*' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $ficheiro) { Write-Host "sem logs em $dir"; break }
    Write-Host "--- $($ficheiro.FullName) (Ctrl+C para sair) ---" -ForegroundColor DarkGray
    Get-Content -LiteralPath $ficheiro.FullName -Tail 40 -Wait
}

}
