[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Write-Host @"
  ██████╗ █████╗ ██████╗ ████████╗███████╗██╗     
  ██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██║     
  ██║     ███████║██████╔╝   ██║   █████╗  ██║     
  ██║     ██╔══██║██╔══██╗   ██║   ██╔══╝  ██║     
  ╚██████╗██║  ██║██║  ██║   ██║   ███████╗███████╗
   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚══════╝╚══════╝
 by xattab (PS Hash Priority v6.4 +VT+HA+MDA+Discord)
----------------------------------------------------
"@ -ForegroundColor Cyan

# ==== КЛЮЧИ (ЗАМЕНИ НА СВОИ) ====
$VTApiKey = "2983518d00a7e56853aa27016e5966a83be5cf95d2d1d6e7466cef82be33f935"
$HAApiKey = "okb7duaid4d743f2lpcpjmph0412da4c516qm6qrf98c3374wcklqyd3e527c25d"
$MDApiKey = "e62d8183f3211a0a4068c3bb7ea7210b"
$DiscordWebhook = "https://discordapp.com/api/webhooks/1396540655668428972/8LvqJPI0PJhld_YGrtGvI0GbDJie-7niFDMcCbZi5O3mJeeV6NuTmOn2jsGNANixjUVa"

# ==== ЛОГИКА WEBHOOK ====
function Send-DiscordWebhook {
    param (
        [string]$content
    )
    try {
        Invoke-RestMethod -Uri $DiscordWebhook -Method Post -ContentType 'application/json' -Body (@{content = $content } | ConvertTo-Json)
    } catch {}
}

# ==== Путь к 7z ====
$SevenZipPath = ""
$possiblePaths = @(
    "$env:ProgramFiles\7-Zip\7z.exe",
    "$env:ProgramFiles(x86)\7-Zip\7z.exe",
    "$env:LOCALAPPDATA\Programs\7-Zip\7z.exe"
)
foreach ($p in $possiblePaths) { if (Test-Path $p) { $SevenZipPath = $p; break } }
if (-not $SevenZipPath) {
    try {
        $null = & "7z.exe" -h 2>$null
        $SevenZipPath = "7z.exe"
    } catch {
        Write-Host "Не удалось найти 7z.exe автоматически." -ForegroundColor Yellow
        do {
            $SevenZipPath = Read-Host "Введите полный путь к 7z.exe (например, D:\MyTools\7z.exe)"
            if (-not (Test-Path $SevenZipPath)) {
                Write-Host "Файл $SevenZipPath не найден! Попробуйте снова." -ForegroundColor Red
                $SevenZipPath = ""
            }
        } while (-not $SevenZipPath)
    }
}

# ==== Путь к файлу хэшей ====
$hashfile = Read-Host "Введите путь к файлу с хешами (или Enter для hashes.txt)"
if ([string]::IsNullOrWhiteSpace($hashfile)) { $hashfile = "hashes.txt" }
if (-not (Test-Path $hashfile)) {
    Write-Host "Файл $hashfile не найден!" -ForegroundColor Red
    Write-Host "Создайте файл в формате: md5:... sha256:... size:..." -ForegroundColor Yellow
    Read-Host "Нажмите Enter для выхода"
    exit
}

# ==== Настройки ====
$extensions = @("exe","dll","ahk","asi","js","bat","cmd","scr","sys","msi","bin","zip","rar","txt","log","cfg","conf","ini","py","vbs","ps1","psm1","ocx","com","7z","drv","tar","gz","xz","bz2")
$archiveExts = @("zip", "rar", "7z", "tar", "gz", "xz", "bz2")
$cloudCheckExts = @("exe", "dll", "ahk")
$logfile = Join-Path $PSScriptRoot "found_files_hash_priority.log"
if (Test-Path $logfile) { Remove-Item $logfile -Force }

function Write-Log {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Add-Content -Path $logfile -Encoding UTF8
    Write-Host $Message
}

# ==== Загрузка хэшей ====
Write-Host "Загрузка хешей..." -ForegroundColor Yellow
$hashData = @(); $lineCount = 0
Get-Content $hashfile -Encoding UTF8 | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith("#")) {
        $lineCount++
        $hashInfo = @{ MD5 = $null; SHA256 = $null; Size = $null; OriginalLine = $line }
        $line -split '\s+' | ForEach-Object {
            if ($_ -match '^md5:([a-fA-F0-9]+)$')       { $hashInfo.MD5    = $matches[1].ToUpper() }
            elseif ($_ -match '^sha256:([a-fA-F0-9]+)$'){ $hashInfo.SHA256 = $matches[1].ToUpper() }
            elseif ($_ -match '^size:(\d+)$')           { $hashInfo.Size   = [long]$matches[1]    }
        }
        $hashData += $hashInfo
    }
}
Write-Host "Загружено $lineCount записей для поиска." -ForegroundColor Green

$md5Index = @{}; $sha256Index = @{}; $sizeIndex = @{}
foreach ($item in $hashData) {
    if ($item.MD5)    { $md5Index[$item.MD5] = $item }
    if ($item.SHA256) { $sha256Index[$item.SHA256] = $item }
    if ($item.Size)   {
        if (-not $sizeIndex.ContainsKey($item.Size)) { $sizeIndex[$item.Size] = @() }
        $sizeIndex[$item.Size] += $item
    }
}

# ==== Сбор статистики ====
$global:scanStats = @{
    TotalFiles = 0
    MD5 = 0
    SHA256 = 0
    SIZE = 0
    DetectedFiles = @()
    StartTime = Get-Date
}

# ==== ФУНКЦИИ ОБЛАЧНЫХ ПРОВЕРОК ====
function Check-VirusTotalHash {
    param([string]$sha256, [string]$path)
    if (-not $VTApiKey) { return }
    $headers = @{ "x-apikey" = $VTApiKey }
    $url = "https://www.virustotal.com/api/v3/files/$sha256"
    try {
        $resp = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -TimeoutSec 10
        $malicious = $resp.data.attributes.last_analysis_stats.malicious
        $suspicious = $resp.data.attributes.last_analysis_stats.suspicious
        if ($malicious -gt 0 -or $suspicious -gt 0) {
            $msg = "⚠️ VirusTotal DETECTED! $path ($malicious mal, $suspicious susp)"
            Write-Host $msg -ForegroundColor Red
            $global:scanStats.DetectedFiles += $msg
            Send-DiscordWebhook "$msg"
        }
        return "$malicious mal / $suspicious susp"
    } catch { return }
}
function Check-HybridAnalysisHash {
    param([string]$sha256, [string]$path)
    if (-not $HAApiKey) { return }
    $headers = @{ "api-key" = $HAApiKey }
    $url = "https://www.hybrid-analysis.com/api/v2/search/hash?hash=$sha256"
    try {
        $resp = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -TimeoutSec 10
        if ($resp.result -and $resp.result.Count -gt 0) {
            $score = $resp.result[0].threat_score
            if ($score -ge 75) {
                $msg = "⚠️ HybridAnalysis DETECTED! $path (score=$score)"
                Write-Host $msg -ForegroundColor Red
                $global:scanStats.DetectedFiles += $msg
                Send-DiscordWebhook "$msg"
            }
            return "score=$score"
        }
    } catch { return }
}
function Check-MetaDefenderHash {
    param([string]$sha256, [string]$path)
    if (-not $MDApiKey) { return }
    $headers = @{ "apikey" = $MDApiKey }
    $url = "https://api.metadefender.com/v4/hash/$sha256"
    try {
        $resp = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -TimeoutSec 10
        $result = $resp.scan_results.scan_all_result_a
        if ($result -eq "Infected") {
            $msg = "⚠️ MetaDefender DETECTED! $path"
            Write-Host $msg -ForegroundColor Red
            $global:scanStats.DetectedFiles += $msg
            Send-DiscordWebhook "$msg"
        }
        return $result
    } catch { return }
}

# ==== РЕКУРСИВНАЯ РАСПАКОВКА АРХИВОВ С ЛИМИТОМ ГЛУБИНЫ ====
function Unpack-And-Scan {
    param (
        [string]$ArchivePath,
        [string]$TempRoot,
        [int]$Depth = 1
    )
    if ($Depth -gt 3) {
        Write-Host "Достигнут лимит глубины распаковки для $ArchivePath" -ForegroundColor DarkYellow
        return
    }
    if (-not $SevenZipPath) {
        Write-Host "7z.exe не найден, пропуск архива $ArchivePath" -ForegroundColor Red
        return
    }
    $TempDir = Join-Path $TempRoot ([guid]::NewGuid().ToString())
    try {
        $proc = Start-Process -FilePath $SevenZipPath -ArgumentList "x `"$ArchivePath`" -o`"$TempDir`" -y" -Wait -NoNewWindow -WindowStyle Hidden -PassThru
        if ($proc.ExitCode -ne 0) {
            Write-Host "Ошибка при распаковке архива $ArchivePath" -ForegroundColor Red
            return
        }
        $unpackedFiles = Get-ChildItem -Path $TempDir -File -Recurse -ErrorAction SilentlyContinue
        foreach ($f in $unpackedFiles) {
            Scan-File $f.FullName $true $Depth
            $ext = [IO.Path]::GetExtension($f.FullName).TrimStart('.').ToLower()
            if ($archiveExts -contains $ext) {
                Write-Host "Рекурсивно открываем архив внутри архива: $($f.FullName) (уровень $Depth)" -ForegroundColor Magenta
                Unpack-And-Scan $f.FullName $TempRoot ($Depth + 1)
            }
        }
    } catch {
        Write-Host "Ошибка при распаковке архива $ArchivePath" -ForegroundColor Red
    }
    Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}


# ==== СКАН ФАЙЛА ====
function Scan-File {
    param (
        [string]$FilePath,
        [bool]$FromArchive = $false,
        [int]$Depth = 1
    )
    $ext = [IO.Path]::GetExtension($FilePath).TrimStart('.').ToLower()
    if (-not $extensions -contains $ext) { return }
    try {
        $md5 = (Get-FileHash -Path $FilePath -Algorithm MD5 -ErrorAction Stop).Hash
        $sha256 = (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
        $fileSize = (Get-Item $FilePath).Length
    } catch { return }
    $global:scanStats.TotalFiles++

    $found = $false
    if ($md5Index.ContainsKey($md5)) {
        $found = $true
        $global:scanStats.MD5++
        $msg = "[MD5 MATCH] $FilePath"
        Write-Host $msg -ForegroundColor Green
        Write-Log $msg
        Send-DiscordWebhook "$msg"
    }
    if ($sha256Index.ContainsKey($sha256)) {
        $found = $true
        $global:scanStats.SHA256++
        $msg = "[SHA256 MATCH] $FilePath"
        Write-Host $msg -ForegroundColor Yellow
        Write-Log $msg
        Send-DiscordWebhook "$msg"
    }
    if ($sizeIndex.ContainsKey($fileSize)) {
        $sizeMatches = $sizeIndex[$fileSize] | Where-Object { -not $_.MD5 -and -not $_.SHA256 }
        if ($sizeMatches) {
            $found = $true
            $global:scanStats.SIZE++
            $msg = "[SIZE ONLY MATCH] $FilePath"
            Write-Host $msg -ForegroundColor Cyan
            Write-Log $msg
            Send-DiscordWebhook "$msg"
        }
    }

    # --- Облачные проверки только для exe/dll/ahk ---
    if ($cloudCheckExts -contains $ext -and $sha256.Length -gt 0) {
        Check-VirusTotalHash $sha256 $FilePath
        Check-HybridAnalysisHash $sha256 $FilePath
        Check-MetaDefenderHash $sha256 $FilePath
    }

    if ($archiveExts -contains $ext -and $Depth -lt 3) {
        Unpack-And-Scan $FilePath $env:TEMP ($Depth + 1)
    }
}
# ==== СКАНИРОВАНИЕ ====
$driveRoots = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -in 2,3,4,5 } | ForEach-Object { $_.DeviceID + "\" }

foreach ($root in $driveRoots) {
    Write-Host "--- Сканирование диска $root ---" -ForegroundColor Yellow
    try {
        $files = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
            $ext = $_.Extension.TrimStart('.').ToLower()
            $extensions -contains $ext
        }
        foreach ($file in $files) {
            Write-Host ("[ПРОВЕРЕНО: {0}] {1}" -f $global:scanStats.TotalFiles, $file.FullName) -ForegroundColor DarkGray
            Scan-File $file.FullName $false 1
        }
    } catch {
        Write-Host "  Ошибка доступа к диску или папке" -ForegroundColor DarkRed
    }
}

# ==== ФИНАЛЬНЫЙ ОТЧЁТ ====
$global:scanStats.EndTime = Get-Date
$seconds = [int]($global:scanStats.EndTime - $global:scanStats.StartTime).TotalSeconds
$msg = @"
**KESH HashPriority Scan Report**
🕒 Время: $($global:scanStats.StartTime) - $($global:scanStats.EndTime) ($seconds сек)
📁 Просканировано файлов: $($global:scanStats.TotalFiles)
✅ Совпадений по MD5: $($global:scanStats.MD5)
✅ Совпадений по SHA256: $($global:scanStats.SHA256)
✅ Совпадений по SIZE: $($global:scanStats.SIZE)
🚨 Детектов антивирусов: $(@($global:scanStats.DetectedFiles).Count)
"@
if ($global:scanStats.DetectedFiles.Count -gt 0) {
    $msg += "`n**Детекты:**`n"
    foreach ($line in $global:scanStats.DetectedFiles) { $msg += "$line`n" }
}
Send-DiscordWebhook $msg
Write-Host $msg -ForegroundColor Cyan

if (Test-Path $logfile) {
    Write-Host ""
    Write-Host "Результаты сохранены в: $logfile" -ForegroundColor White
}
Write-Host "======================================" -ForegroundColor Cyan

Read-Host "Нажмите Enter для выхода"
