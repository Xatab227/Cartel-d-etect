# KESH-HashPriority.ps1
# Установка кодировки UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Логотип
Write-Host @"
  ██████╗ █████╗ ██████╗ ████████╗███████╗██╗     
  ██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██║     
  ██║     ███████║██████╔╝   ██║   █████╗  ██║     
  ██║     ██╔══██║██╔══██╗   ██║   ██╔══╝  ██║     
  ╚██████╗██║  ██║██║  ██║   ██║   ███████╗███████╗
   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚══════╝
         by xattab (PS Hash Priority v3.0)
-----------------------------------------------

"@ -ForegroundColor Cyan

# Запрос пути к файлу с хешами
$hashfile = Read-Host "Введите путь к файлу с хешами (или нажмите Enter для использования hashes.txt)"
if ([string]::IsNullOrWhiteSpace($hashfile)) {
    $hashfile = "hashes.txt"
}

# Проверка существования файла
if (-not (Test-Path $hashfile)) {
    Write-Host "Файл $hashfile не найден!" -ForegroundColor Red
    Write-Host @"

Создайте файл со следующим форматом:
md5:хеш sha256:хеш size:размер

Пример:
md5:ed70564eac1724bba14d49aa25c42872 sha256:62df087222e047640680bf8aae1a2afc68a5f26f606932031ac8b60f34bd95b6 size:23068160
md5:a7e7b360265f50835bd60b5ec414a236 sha256:72c3326b3e05d7b29fa69b4482b9390e1d7cabccb2497ec04961773e05f7eee3 size:13039104
"@
    Read-Host "Нажмите Enter для выхода"
    exit
}

# Настройки
$extensions = @("exe","dll","asi","js","ahk","bat","cmd","scr","sys","msi","bin","zip","rar","txt","log","cfg","conf","ini","py","vbs","ps1","psm1","ocx","com","7z","drv")
$logfile = Join-Path $PSScriptRoot "found_files_hash_priority.log"

# Очистка лога
if (Test-Path $logfile) {
    Remove-Item $logfile -Force
}

# Функция логирования
function Write-Log {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Add-Content -Path $logfile -Encoding UTF8
    Write-Host $Message
}

# Загрузка хешей из файла
Write-Host "Загрузка хешей..." -ForegroundColor Yellow
$hashData = @()
$lineCount = 0

Get-Content $hashfile -Encoding UTF8 | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith("#")) {
        $lineCount++
        $hashInfo = @{
            MD5 = $null
            SHA256 = $null
            Size = $null
            OriginalLine = $line
        }
        
        # Парсинг строки
        $line -split '\s+' | ForEach-Object {
            if ($_ -match '^md5:([a-fA-F0-9]+)$') {
                $hashInfo.MD5 = $matches[1].ToUpper()
            }
            elseif ($_ -match '^sha256:([a-fA-F0-9]+)$') {
                $hashInfo.SHA256 = $matches[1].ToUpper()
            }
            elseif ($_ -match '^size:(\d+)$') {
                $hashInfo.Size = [long]$matches[1]
            }
        }
        
        $hashData += $hashInfo
    }
}

Write-Host "Загружено $lineCount записей для поиска." -ForegroundColor Green
Write-Host ""

# Создание индексов для быстрого поиска
$md5Index = @{}
$sha256Index = @{}
$sizeIndex = @{}

foreach ($item in $hashData) {
    if ($item.MD5) { $md5Index[$item.MD5] = $item }
    if ($item.SHA256) { $sha256Index[$item.SHA256] = $item }
    if ($item.Size) {
        if (-not $sizeIndex.ContainsKey($item.Size)) {
            $sizeIndex[$item.Size] = @()
        }
        $sizeIndex[$item.Size] += $item
    }
}

# Статистика поиска
$stats = @{
    FilesScanned = 0
    MD5Matches = 0
    SHA256Matches = 0
    SizeOnlyMatches = 0
    TotalTime = [System.Diagnostics.Stopwatch]::StartNew()
}

# Получение всех дисков
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne $null }

foreach ($drive in $drives) {
    Write-Host "--- Сканирование диска $($drive.Name): ---" -ForegroundColor Yellow
    
    foreach ($ext in $extensions) {
        Write-Host "  Поиск файлов *.$ext..." -ForegroundColor Gray
        
        try {
            Get-ChildItem -Path "$($drive.Root)" -Filter "*.$ext" -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $file = $_
                $stats.FilesScanned++
                
                if ($stats.FilesScanned % 100 -eq 0) {
                    Write-Host "    Проверено файлов: $($stats.FilesScanned)" -ForegroundColor DarkGray
                }
                
                try {
                    # Проверка по MD5
                    $md5 = (Get-FileHash -Path $file.FullName -Algorithm MD5 -ErrorAction Stop).Hash
                    
                    if ($md5Index.ContainsKey($md5)) {
                        $matchInfo = $md5Index[$md5]
                        Write-Log "[MD5 MATCH] $($file.FullName)"
                        Write-Log "  Найдено по MD5: $md5"
                        Write-Log "  Исходная запись: $($matchInfo.OriginalLine)"
                        Write-Host "[MD5 MATCH] $($file.FullName)" -ForegroundColor Green
                        $stats.MD5Matches++
                    }

                    # Проверка по SHA256
                    $sha256 = (Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
                    
                    if ($sha256Index.ContainsKey($sha256)) {
                        $matchInfo = $sha256Index[$sha256]
                        Write-Log "[SHA256 MATCH] $($file.FullName)"
                        Write-Log "  Найдено по SHA256: $sha256"
                        Write-Log "  Исходная запись: $($matchInfo.OriginalLine)"
                        Write-Host "[SHA256 MATCH] $($file.FullName)" -ForegroundColor Yellow
                        $stats.SHA256Matches++
                    }

                    # Проверка только по размеру
                    $fileSize = $file.Length
                    if ($sizeIndex.ContainsKey($fileSize)) {
                        $sizeMatches = $sizeIndex[$fileSize] | Where-Object { -not $_.MD5 -and -not $_.SHA256 }
                        
                        if ($sizeMatches) {
                            Write-Log "[SIZE ONLY MATCH] $($file.FullName)"
                            Write-Log "  Найдено по размеру: $fileSize байт"
                            Write-Log "  Вычисленные хеши - MD5: $md5, SHA256: $sha256"
                            foreach ($match in $sizeMatches) {
                                Write-Log "  Возможное совпадение: $($match.OriginalLine)"
                            }
                            Write-Host "[SIZE ONLY MATCH] $($file.FullName)" -ForegroundColor Cyan
                            $stats.SizeOnlyMatches++
                        }
                    }
                }
                catch {
                    Write-Host "    Ошибка обработки: $($file.FullName)" -ForegroundColor DarkRed
                }
            }
        }
        catch {
            Write-Host "  Ошибка доступа к диску или папке" -ForegroundColor DarkRed
        }
    }
}

# Остановка таймера
$stats.TotalTime.Stop()

# Итоговая статистика
Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Сканирование завершено!" -ForegroundColor Green
Write-Host "Время выполнения: $($stats.TotalTime.Elapsed.ToString())" -ForegroundColor White
Write-Host "Проверено файлов: $($stats.FilesScanned)" -ForegroundColor White
Write-Host "Найдено совпадений:" -ForegroundColor White
Write-Host "  - По MD5: $($stats.MD5Matches)" -ForegroundColor Green
Write-Host "  - По SHA256: $($stats.SHA256Matches)" -ForegroundColor Yellow
Write-Host "  - Только по размеру: $($stats.SizeOnlyMatches)" -ForegroundColor Cyan
Write-Host "Всего совпадений: $($stats.MD5Matches + $stats.SHA256Matches + $stats.SizeOnlyMatches)" -ForegroundColor White

if (Test-Path $logfile) {
    Write-Host ""
    Write-Host "Результаты сохранены в: $logfile" -ForegroundColor White
}
Write-Host "======================================" -ForegroundColor Cyan

Read-Host "Нажмите Enter для выхода"