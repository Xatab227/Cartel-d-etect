
# ==========================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Set-Location -Path $PSScriptRoot
# Настройка параметров
$trustedHashes = Import-Csv "trusted_driver_hashes.csv"
$apiKey = "2983518d00a7e56853aa27016e5966a83be5cf95d2d1d6e7466cef82be33f935"
# === Инициализация логов ===
$log = "$PSScriptRoot\hwid_pro_ps.log"
$baseInfoLog = "$PSScriptRoot\hwid_base_info.log"
$suspectLog = "$PSScriptRoot\hwid_suspects.log"
$reportFile = "$PSScriptRoot\hwid_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$date = Get-Date -Format "yyyy-MM-dd HH:mm:ss" 
# === Запуск принудильных прав админа ===
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole] "Administrator")) {
    Write-Host "Перезапуск от имени администратора..." -ForegroundColor Yellow
    $script = $MyInvocation.MyCommand.Definition
    Start-Process powershell.exe "-ExecutionPolicy Bypass -File `"$script`"" -Verb RunAs
    exit
}

Write-Host @"
  ██████╗ █████╗ ██████╗ ████████╗███████╗██╗     
  ██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██║     
  ██║     ███████║██████╔╝   ██║   █████╗  ██║     
  ██║     ██╔══██║██╔══██╗   ██║   ██╔══╝  ██║     
  ╚██████╗██║  ██║██║  ██║   ██║   ███████╗███████╗
   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚══════╝╚══════╝
         by xattab (PS HWID Pro Check v4.7 Ultra)
-----------------------------------------------
"@ -ForegroundColor Cyan

"==== HWID Pro Check (PowerShell Ultra) - $date ====" | Tee-Object -FilePath $log -Append
"==== БАЗОВАЯ ИНФОРМАЦИЯ О СИСТЕМЕ - $date ====" | Out-File -FilePath $baseInfoLog
"==== ПОДОЗРЕНИЯ НА СПУФИНГ - $date ====" | Out-File -FilePath $suspectLog

# ========== Сбор базовой информации ==========
Write-Host "Получение общей информации о системе..." -ForegroundColor Cyan
Get-CimInstance Win32_ComputerSystem | Format-List | Out-String | Tee-Object -Append -FilePath $log | Out-File -Append -FilePath $baseInfoLog
Get-CimInstance Win32_OperatingSystem | Format-List | Out-String | Tee-Object -Append -FilePath $log | Out-File -Append -FilePath $baseInfoLog

Write-Host "Получение информации о BIOS и материнской плате..." -ForegroundColor Cyan
$bios = Get-CimInstance Win32_BIOS
$bios | Format-List | Out-String | Tee-Object -Append -FilePath $log | Out-File -Append -FilePath $baseInfoLog
$baseboard = Get-CimInstance Win32_BaseBoard
$baseboard | Format-List | Out-String | Tee-Object -Append -FilePath $log | Out-File -Append -FilePath $baseInfoLog

Write-Host "Получение информации о процессоре..." -ForegroundColor Cyan
$cpu = Get-CimInstance Win32_Processor
$cpu | Format-List | Out-String | Tee-Object -Append -FilePath $log | Out-File -Append -FilePath $baseInfoLog

Write-Host "Получение информации о видеокарте..." -ForegroundColor Cyan
$video = Get-CimInstance Win32_VideoController
$video | Format-List | Out-String | Tee-Object -Append -FilePath $log | Out-File -Append -FilePath $baseInfoLog

Write-Host "Получение информации о дисках..." -ForegroundColor Cyan
$disks = Get-CimInstance Win32_DiskDrive
$disks | Format-List | Out-String | Tee-Object -Append -FilePath $log | Out-File -Append -FilePath $baseInfoLog

Write-Host "Получение MAC-адресов и информации о сетевых адаптерах..." -ForegroundColor Cyan
$adapters = Get-NetAdapter
$adapters | Format-List Name, MacAddress, Status, InterfaceDescription | Out-String | Tee-Object -Append -FilePath $log | Out-File -Append -FilePath $baseInfoLog

# ==========================hollows_hunter (доп анализ ОЗУ)

function Run-HollowsHunter {
    param(
        [string]$HollowsHunterPath = ".\hollows_hunter.exe",
        [string]$OutputReport = ".\hollows_report.json"
    )
    if (!(Test-Path $HollowsHunterPath)) {
        Write-Host "hollows_hunter.exe не найден по пути $HollowsHunterPath" -ForegroundColor Red
        return
    }

    $arguments = @(
        "/json",
        "/jlvl", "2",
        "/hooks",
        "/iat", "3",
        "/shellc", "4",
        "/threads",
        "/obfusc", "3",
        "/data", "4"
    )

    Write-Host "`n[Hollows Hunter] Запуск сканирования всех процессов (максимальный режим)..."
    try {
        & $HollowsHunterPath @arguments | Set-Content $OutputReport
    } catch {
        Write-Host "[Hollows Hunter] Ошибка запуска или записи отчета!" -ForegroundColor Yellow
        return
    }

    if (!(Test-Path $OutputReport)) {
        Write-Host "[Hollows Hunter] Отчет не найден: $OutputReport" -ForegroundColor Yellow
        return
    }
    try {
        $report = Get-Content $OutputReport -Raw | ConvertFrom-Json
    } catch {
        Write-Host "[Hollows Hunter] Ошибка при чтении/парсинге JSON отчета!" -ForegroundColor Red
        return
    }

    Write-Host "`n[Hollows Hunter] Найдены подозрительные процессы:`n" -ForegroundColor Cyan

    $suspiciousCount = 0
    foreach ($scan in $report.scans) {
        $reflectionFailed = $scan.reflection -eq $false
        if ($scan.suspicious -eq $true -or $scan.suspicious_modules.Count -gt 0 -or $reflectionFailed) {
            $suspiciousCount++
            Write-Host ("[{0}] PID: {1} | Name: {2}" -f $suspiciousCount, $scan.pid, $scan.process)
            if ($scan.suspicious_reason) {
                Write-Host ("    Причина: {0}" -f $scan.suspicious_reason) -ForegroundColor Yellow
            }
            if ($scan.suspicious_modules.Count -gt 0) {
                Write-Host ("    Модули: " + ($scan.suspicious_modules -join ', ')) -ForegroundColor Yellow
            }
            if ($reflectionFailed) {
                Write-Host ("    ⚠️ Reflection не удался для процесса (возможна защита): PID $($scan.pid)") -ForegroundColor Magenta
            }
            Write-Host ""
        }
    }
    if ($suspiciousCount -eq 0) {
        Write-Host "Ничего подозрительного не найдено." -ForegroundColor Green
    }
}

# Запуск проверки можно делать в любом месте скрипта:
Run-HollowsHunter
#===========
function Check-DriverHashWithVirusTotal {
    param (
        [string]$driverPath
    )

    if (-not (Test-Path $driverPath)) {
        return "❌ Файл не найден"
    }

    try {
        $hash = Get-FileHash -Path $driverPath -Algorithm SHA256
        $sha256 = $hash.Hash.ToLower()

        # Проверка в оффлайн-базе (если используете trusted_driver_hashes.csv)
        if ($trustedHashes -and ($trustedHashes | Where-Object { $_.SHA256 -eq $sha256 })) {
            return "🟢 Совпадает с trusted_driver_hashes.csv"
        }

        # Если используете VirusTotal API
        if ($apiKey) {
            $vtHeaders = @{
                "x-apikey" = $apiKey
            }
            $vtUri = "https://www.virustotal.com/api/v3/files/$sha256"
            $vtResponse = Invoke-RestMethod -Uri $vtUri -Headers $vtHeaders -Method Get -ErrorAction Stop
            $positives = $vtResponse.data.attributes.last_analysis_stats.malicious
            if ($positives -gt 0) {
                return "🔴 Опасно ($positives детектов)"
            } else {
                return "🟢 Безопасно (0 детектов)"
            }
        } else {
            return "⚠️ Нет API ключа — VT пропущен"
        }
    } catch {
        return "⚠️ Ошибка VirusTotal-запроса или проверки: $_"
    }
}

Write-Host "`n================= SYSTEM SECURITY ANALYSIS =================" -ForegroundColor Cyan

### 1. Secure Boot Status--------------------------------------------------------
try {
    $sb = Confirm-SecureBootUEFI
    if ($sb) {
        Write-Host "[✓] Secure Boot: ENABLED" -ForegroundColor Green
    } else {
        Write-Host "[!] Secure Boot: DISABLED (⚠️ возможен DSE Bypass)" -ForegroundColor Yellow
        $alerts++
    }
} catch {
    Write-Host "[?] Secure Boot: НЕ ПОДДЕРЖИВАЕТСЯ или отключен UEFI" -ForegroundColor DarkYellow
    $alerts++
}

### 2. Проверка включена ли проверка цифровых подписей драйверов (DSE)
$dseStatus = (bcdedit | Where-Object { $_ -match "nointegritychecks" })
if ($dseStatus -match "Yes") {
    Write-Host "[!] DSE (проверка подписей драйверов): ОТКЛЮЧЕНА ⚠️" -ForegroundColor Red
    $alerts++
} else {
    Write-Host "[✓] DSE (Driver Signature Enforcement): ВКЛЮЧЕН" -ForegroundColor Green
}

### 3. Анализ ACPI-таблиц (поверхностный через WMI)
try {
    $acpiTables = Get-WmiObject -Namespace "root\wmi" -Class "MSAcpi_ThermalZoneTemperature"
    if ($acpiTables.Count -gt 0) {
        Write-Host "[✓] ACPI WMI-доступ активен" -ForegroundColor Green
    } else {
        Write-Host "[!] Нет доступа к ACPI таблицам через WMI (возможна подмена таблиц или отключение)" -ForegroundColor Yellow
        $alerts++
    }
} catch {
    Write-Host "[!] Ошибка доступа к ACPI WMI — возможно скрытие или редактирование таблиц" -ForegroundColor Red
    $alerts++
}

### 4. Обнаружение потенциальных загрузчиков DSE-байпасов (Capcom, intelmap, kdmapper)
$knownBypassDrivers = @("capcom.sys", "iqvw64e.sys", "gdrv.sys", "dbk64.sys", "intelmap.sys", "rtcore64.sys")
$loadedDrivers = Get-WmiObject Win32_SystemDriver | Select-Object -ExpandProperty PathName

foreach ($driver in $knownBypassDrivers) {
    if ($loadedDrivers -match $driver) {
        Write-Host "[!] Найден возможный DSE bypass-драйвер: $driver" -ForegroundColor Red
        $alerts++
    }
}
#Проверки для виртуальных машин
function Check-VirtualMachine {
    $vmDrivers = Get-ChildItem "C:\Windows\System32\drivers" -Filter "*vmbus*"
    if ($vmDrivers.Count -gt 0) {
        Write-Host "Обнаружена виртуальная машина!" -ForegroundColor Red
    }
}

# Вывод суммарного статуса
Write-Host "`n================= SPOOFING RISK SCORE =================" -ForegroundColor Cyan
if ($alerts -ge 3) {
    Write-Host "⚠️  ВОЗМОЖЕН СПУФИНГ / ОБХОД ЗАЩИТЫ ЯДРА — $alerts подозрительных признаков" -ForegroundColor Red
} elseif ($alerts -eq 0) {
    Write-Host "✅  Спуфинг или модификация ядра не обнаружены." -ForegroundColor Green
} else {
    Write-Host "⚠️  Подозрительные признаки: $alerts — проверьте вручную." -ForegroundColor Yellow
}
#Проверка состояния антивируса ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Write-Host "Проверка антивирусной защиты..." -ForegroundColor Cyan

try {
    $avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntivirusProduct -ErrorAction Stop
    foreach ($av in $avProducts) {
        $avState = switch ($av.productState) {
            {$_ -band 0x10} {"Отключен"}
            default {"Включен"}
        }
        $avMsg = "Антивирус: $($av.displayName) ($av.pathToSignedProductExe) — $avState"
        Add-Content $baseInfoLog $avMsg
        if ($avState -eq "Отключен") { Add-Content $suspectLog "[ОТКЛЮЧЕН АНТИВИРУС] $avMsg" }
    }
} catch {
    Add-Content $baseInfoLog "Не удалось получить информацию об антивирусе"
}
#Проверка Ransomware Protection (Контролируемый доступ к папкам)
Write-Host "Проверка Ransomware Protection..." -ForegroundColor Cyan

try {
    $RansomStatus = Get-MpPreference | Select-Object -ExpandProperty ControlledFolderAccessProtectedFolders
    if ($RansomStatus) {
        Add-Content $baseInfoLog "Ransomware Protection (контролируемый доступ к папкам): ВКЛЮЧЕН"
    } else {
        Add-Content $suspectLog "[ОТКЛЮЧЕН Ransomware Protection] — Контролируемый доступ к папкам отключен"
        Add-Content $baseInfoLog "Ransomware Protection: выключен"
    }
} catch {
    Add-Content $baseInfoLog "Не удалось получить статус Ransomware Protection"
}
# Проверка статуса UAC
Write-Host "Проверка статуса UAC..." -ForegroundColor Cyan

try {
    $uacLevel = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA
    if ($uacLevel.EnableLUA -eq 0) {
        Add-Content $suspectLog "[UAC ОТКЛЮЧЁН] User Account Control выключен."
        Add-Content $baseInfoLog "UAC: выключен"
    } else {
        Add-Content $baseInfoLog "UAC: включён"
    }
} catch {
    Add-Content $baseInfoLog "Не удалось получить статус UAC"
}
#Чек политики аудита и журналов безопасности
Write-Host "Проверка политики аудита и журналов безопасности..." -ForegroundColor Cyan

try {
    $auditPolicy = AuditPol /get /category:* | Out-String
    Add-Content $baseInfoLog "Аудит политики безопасности:"
    Add-Content $baseInfoLog $auditPolicy

    # Краткий анализ некоторых подозрительных моментов
    if ($auditPolicy -match "НЕТ") {
        Add-Content $suspectLog "[АУДИТ ОТКЛЮЧЕН] В политике аудита есть отключённые параметры"
    }
# Проверка на активность TPM
function Get-TPM {
    try {
        $tpmStatus = Get-WmiObject -Class Win32_Tpm -ErrorAction Stop
        if ($tpmStatus.TpmPresent -eq $true -and $tpmStatus.TpmEnabled -eq $true) {
            Write-Host "TPM активен." -ForegroundColor Green
            return $true
        } else {
            Write-Host "TPM не активен или не доступен." -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "TPM не доступен или класс Win32_Tpm отсутствует на этой системе." -ForegroundColor Yellow
        return $false
    }
}

# Проверка на события в журнале Microsoft-Windows-CodeIntegrity/Operational
function Check-CodeIntegrityEvents {
    try {
        $events = Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -MaxEvents 10 -ErrorAction SilentlyContinue
        if ($events) {
            Write-Host "Обнаружены события CodeIntegrity:" -ForegroundColor Red
            $events | ForEach-Object { Write-Host $_.Message -ForegroundColor Red }
        } else {
            Write-Host "Не найдено событий для проверки." -ForegroundColor Green
        }
    } catch {
        Write-Host "Не удалось получить события из журнала Microsoft-Windows-CodeIntegrity/Operational." -ForegroundColor Red
    }
}

# Проверка файлов .dll и .exe в C:\Windows\System32 (для обнаружения hooking tools)
function Check-HookingTools {
    try {
        $files = Get-ChildItem -Path "C:\Windows\System32" -Filter "*.dll" -Recurse -ErrorAction SilentlyContinue
        $files += Get-ChildItem -Path "C:\Windows\System32" -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue
        $suspectFiles = $files | Where-Object { $_.Name -match "hook" -or $_.Name -match "bypass" }

        if ($suspectFiles.Count -gt 0) {
            Write-Host "Обнаружены подозрительные .dll и .exe файлы:" -ForegroundColor Red
            $suspectFiles | ForEach-Object { Write-Host $_.FullName -ForegroundColor Red }
        } else {
            Write-Host "Не обнаружено подозрительных .dll и .exe файлов." -ForegroundColor Green
        }
    } catch {
        Write-Host "Не удалось получить доступ к файлам в C:\Windows\System32." -ForegroundColor Red
    }
}

# Проверка изменений с помощью bcdedit (testsigning, nointegritychecks)
function Check-BCDEdit {
    try {
        $bcdeditOutput = bcdedit /enum
        if ($bcdeditOutput -match "testsigning\s+Yes") {
            Write-Host "Режим тестирования включен (testsigning)." -ForegroundColor Red
        } else {
            Write-Host "Режим тестирования не включен." -ForegroundColor Green
        }

        if ($bcdeditOutput -match "nointegritychecks\s+Yes") {
            Write-Host "Целостность системы отключена (nointegritychecks)." -ForegroundColor Red
        } else {
            Write-Host "Целостность системы включена." -ForegroundColor Green
        }
    } catch {
        Write-Host "Не удалось получить информацию из bcdedit." -ForegroundColor Red
    }
}


# ==========================
# UEFI & Hypervisor Detection Enhancements
# ==========================

function Detect-Hypervisor {
    try {
        $cpuInfo = Get-CimInstance Win32_Processor
        if ($cpuInfo.VirtualizationFirmwareEnabled -eq $true) {
            Write-Host "[!] VirtualizationFirmwareEnabled = TRUE" -ForegroundColor Yellow
        }

        $output = (cmd /c "wmic cpu get VirtualizationFirmwareEnabled /value") -join ""
        if ($output -match "TRUE") {
            Write-Host "[!] CPUID Hypervisor Bit Detected (VM or Hypervisor Present)" -ForegroundColor Red
        } else {
            Write-Host "[✓] Hypervisor Bit not present" -ForegroundColor Green
        }
    } catch {
        Write-Host "[?] Не удалось получить CPUID Hypervisor Bit" -ForegroundColor DarkYellow
    }
}

function Detect-UEFI-Spoofing {
    try {
        $tables = Get-CimInstance -Namespace "root\WMI" -ClassName "MSAcpi_TableInformation"
        foreach ($t in $tables) {
            if ($t.OemId -match "BOCHS|VBOX|QEMU|KVM|XEN|AEMU") {
                Write-Host "[!] ACPI таблица содержит VM/эмулятор OEM ID: $($t.OemId)" -ForegroundColor Red
            }
        }
    } catch {
        Write-Host "[!] Ошибка при проверке ACPI OEM ID" -ForegroundColor DarkYellow
    }
}

function Timing-TSC {
    $time = Measure-Command {
        for ($i = 0; $i -lt 1000000; $i++) { $null = [math]::Sqrt($i) }
    }
    if ($time.TotalMilliseconds -lt 25) {
        Write-Host "[!] Время слишком быстрое ($($time.TotalMilliseconds) мс) — возможно эмуляция CPU" -ForegroundColor Yellow
    } else {
        Write-Host "[✓] Время выполнения соответствует ожиданиям" -ForegroundColor Green
    }
}

function Check-UEFI-Logs {
    try {
        $events = Get-WinEvent -LogName "Microsoft-Windows-Kernel-Boot/Operational" -MaxEvents 100 | 
                  Where-Object { $_.Id -in 105, 103 }

        foreach ($evt in $events) {
            Write-Host "[UEFI] SecureBoot Event: $($evt.Id) - $($evt.Message)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Журнал SecureBoot недоступен" -ForegroundColor DarkYellow
    }
}

# Integrate into main check
function Run-HwidChecks {
    Get-TPM
    Check-CodeIntegrityEvents
    Check-HookingTools
    Check-BCDEdit
    Detect-Hypervisor
    Detect-UEFI-Spoofing
    Timing-TSC
    Check-UEFI-Logs
}


# Основной блок: выполняем все проверки
function Run-HwidChecks {
    # Проверка на активность TPM
    Get-TPM

    # Проверка на события DSE bypass и модификации ядра
    Check-CodeIntegrityEvents

    # Проверка на наличие подозрительных файлов .dll и .exe в System32
    Check-HookingTools

    # Проверка на изменения в bcdedit
    Check-BCDEdit
}

# Выполняем все проверки
Run-HwidChecks

    # Проверка очистки журналов безопасности за последние сутки
    $logClears = Get-WinEvent -LogName Security -MaxEvents 500 | Where-Object { $_.Id -eq 1102 }
    if ($logClears) {
        foreach ($clear in $logClears) {
            $clearMsg = "[ОЧИСТКА ЖУРНАЛА] Security log очищался: $($clear.TimeCreated)"
            Add-Content $suspectLog $clearMsg
            Add-Content $baseInfoLog $clearMsg
        }
    }
} catch {
    Add-Content $baseInfoLog "Не удалось проверить аудит и журналы безопасности"
}
#PolicyIntegrity событий
Write-Host "Проверка PolicyIntegrity событий..." -ForegroundColor Cyan

try {
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4657}
    foreach ($event in $events) {
        $eventMsg = "[ИНТЕГРИТИ ПОЛИТИКИ] Обнаружено событие ID 4657: $($event.TimeCreated) $($event.Message)"
        Add-Content $suspectLog $eventMsg
        Add-Content $baseInfoLog $eventMsg
    }
} catch {}
#Быстрый ручной анализ suspicious handle
Write-Host "Анализ дескрипторов (ручная зона, требует Sysinternals Handle.exe)..." -ForegroundColor Cyan

$handlePath = "C:\Users\Xat\Desktop\Cartel\SysinternalsSuite\handle.exe"  # путь к handle.exe от Sysinternals
if (Test-Path $handlePath) {
    try {
        $handleOut = & $handlePath | Select-String "spoo"
        if ($handleOut) {
            Add-Content $suspectLog "[HANDLE] Обнаружены подозрительные handle: $handleOut"
        } else {
            Add-Content $baseInfoLog "Handle.exe: подозрительных дескрипторов не найдено."
        }
    } catch {
        Add-Content $baseInfoLog "Handle.exe не удалось запустить."
    }
} else {
    Write-Host "handle.exe не найден по стандартному пути." -ForegroundColor Yellow
    # Запросить путь у пользователя
    $handlePath = Read-Host "Введите путь к файлу handle.exe"
    if (-not (Test-Path $handlePath)) {
        Write-Host "Файл handle.exe не найден." -ForegroundColor Red
        Add-Content $baseInfoLog "handle.exe от Sysinternals не найден, ручной анализ handle пропущен."
    } else {
        Write-Host "Используем путь: $handlePath" -ForegroundColor Green
        try {
            $handleOut = & $handlePath | Select-String "spoo"
            if ($handleOut) {
                Add-Content $suspectLog "[HANDLE] Обнаружены подозрительные handle: $handleOut"
            } else {
                Add-Content $baseInfoLog "Handle.exe: подозрительных дескрипторов не найдено."
            }
        } catch {
            Add-Content $baseInfoLog "Handle.exe не удалось запустить."
        }
    }
}

#Использование sigcheck (анализ подписей драйверов/сервисов)
$sigcheckPath = "C:\Users\Xat\Desktop\Cartel\SysinternalsSuite\sigcheck64.exe"  # Стандартный путь
if (-not (Test-Path $sigcheckPath)) {
    Write-Host "sigcheck.exe не найден по стандартному пути." -ForegroundColor Yellow
    # Запросить у пользователя путь к файлу
    $sigcheckPath = Read-Host "Введите путь к файлу sigcheck64.exe"
    if (-not (Test-Path $sigcheckPath)) {
        Write-Host "Файл sigcheck.exe не найден." -ForegroundColor Red
        Add-Content $baseInfoLog "sigcheck не найден, проверка подписей драйверов пропущена."
        return
    }
    Write-Host "Используем путь: $sigcheckPath" -ForegroundColor Green
}

Write-Host "Проверка подписей драйверов с использованием sigcheck..." -ForegroundColor Cyan
$sysFiles = Get-ChildItem 'C:\Windows\System32\drivers' -Filter '*.sys' -File -ErrorAction SilentlyContinue
foreach ($f in $sysFiles) {
    $siginfo = & $sigcheckPath -q -n $f.FullName
    if ($siginfo -notmatch "Verified") {
        $msg = "[НЕПОДПИСАННЫЙ ДРАЙВЕР] $($f.FullName): $siginfo"
        Add-Content $suspectLog $msg
    }
}

# ========== UEFI BIOS и Secure Boot проверка ==========
Write-Host "Проверка UEFI и Secure Boot..." -ForegroundColor Cyan

# Проверка UEFI через bcdedit
$bcdeditOutput = & bcdedit /enum | Out-String
if ($bcdeditOutput -match "path\s+\\EFI\\") {
    $uefiInfo = "Система загружена в UEFI режиме"
    Add-Content $log $uefiInfo
    Add-Content $baseInfoLog $uefiInfo
    $uefiMode = $true
} else {
    $uefiInfo = "Система загружена в Legacy BIOS режиме"
    Add-Content $log $uefiInfo
    Add-Content $baseInfoLog $uefiInfo
    $uefiMode = $false
}

# Проверка Secure Boot
try {
    $secureBootStatus = Confirm-SecureBootUEFI
    $secureInfo = "Secure Boot статус: $secureBootStatus"
    Add-Content $log $secureInfo
    Add-Content $baseInfoLog $secureInfo
} catch {
    $secureInfo = "Secure Boot: не поддерживается или недоступен"
    Add-Content $log $secureInfo
    Add-Content $baseInfoLog $secureInfo
}

# ========== Анализ теневых устройств (Shadow Devices) ==========
Write-Host "Анализ теневых устройств и времени жизни компонентов..." -ForegroundColor Cyan

$shadowDevices = @()

# Получение всех устройств через WMI
$allDevices = Get-CimInstance Win32_PnPEntity
$deviceHistory = @{}

# Анализ времени установки устройств
foreach ($device in $allDevices) {
    if ($device.InstallDate) {
        $installDate = $device.InstallDate
        $deviceAge = (Get-Date) - $installDate
        
        # Если устройство установлено менее 24 часов назад
        if ($deviceAge.TotalHours -lt 24) {
            $shadowMsg = "Недавно установленное устройство: $($device.Name) - установлено $($deviceAge.TotalHours) часов назад"
            $shadowDevices += $shadowMsg
            Add-Content $suspectLog $shadowMsg
        }
    }
}

# Поиск скрытых устройств через Device Manager
$hiddenDevices = Get-CimInstance Win32_PnPEntity | Where-Object { $_.Status -eq "Unknown" -or $_.Status -eq "Degraded" }
foreach ($hd in $hiddenDevices) {
    $shadowMsg = "Потенциально скрытое устройство: $($hd.Name) - Статус: $($hd.Status)"
    $shadowDevices += $shadowMsg
    Add-Content $suspectLog $shadowMsg
}

# Проверка ghost devices
$ghostDevices = Get-CimInstance Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 }
foreach ($gd in $ghostDevices) {
    $shadowMsg = "Ghost устройство: $($gd.Name) - Код ошибки: $($gd.ConfigManagerErrorCode)"
    $shadowDevices += $shadowMsg
    Add-Content $suspectLog $shadowMsg
}

if ($shadowDevices.Count -gt 0) {
    Add-Content $log "`n==== Обнаружены теневые/подозрительные устройства ===="
    foreach ($sd in $shadowDevices) { Add-Content $log " - $sd" }
}

# ========== Продвинутые техники спуфинга ==========
Write-Host "Проверка продвинутых техник спуфинга..." -ForegroundColor Cyan

$spoofingSigns = @()

# 1. ACPI Table Patch Detection
try {
    $acpiTables = Get-CimInstance -Namespace root\WMI -ClassName MSAcpi_TableInformation -ErrorAction SilentlyContinue
    if ($acpiTables) {
        foreach ($table in $acpiTables) {
            # Проверка на модифицированные ACPI таблицы
            if ($table.Signature -match "DSDT|SSDT") {
                # Анализ OEM ID на подозрительные значения
                if ($table.OemId -match "BOCHS|VBOX|QEMU|VMW") {
                    $spoofMsg = "ACPI таблица содержит VM сигнатуру: $($table.OemId)"
                    $spoofingSigns += $spoofMsg
                    Add-Content $suspectLog $spoofMsg
                }
            }
        }
    }
} catch {}

# 2. Device Guard Bypass Detection
try {
    $deviceGuardStatus = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    if ($deviceGuardStatus) {
        if ($deviceGuardStatus.SecurityServicesRunning -notcontains 1) {
            $spoofMsg = "Device Guard не активен - возможен bypass"
            $spoofingSigns += $spoofMsg
            Add-Content $suspectLog $spoofMsg
        }
    }
} catch {}

# 3. Kernel APC Manipulation Detection
$suspiciousDrivers = @("capcom.sys", "dbutil_2_3.sys", "gdrv.sys", "kdmapper.sys", "nqhvice.sys", "vgk.sys")

foreach ($driver in Get-CimInstance Win32_SystemDriver) {
    $driverName = [System.IO.Path]::GetFileName($driver.PathName).ToLower()
    if ($driverName -in $suspiciousDrivers) {
        $spoofMsg = "Обнаружен драйвер для kernel manipulation: $driverName"
        $spoofingSigns += $spoofMsg
        Add-Content $suspectLog $spoofMsg
    }
}

# ========== Анализ метаданных NTFS ==========
Write-Host "Анализ метаданных NTFS..." -ForegroundColor Cyan

$ntfsAnomalies = @()

# Получение информации о томах
$volumes = Get-CimInstance Win32_Volume | Where-Object { $_.FileSystem -eq "NTFS" -and $_.DriveLetter }

foreach ($volume in $volumes) {
    # Проверка времени создания тома
    if ($volume.InstallDate) {
        $volumeAge = (Get-Date) - $volume.InstallDate
        if ($volumeAge.TotalDays -lt 1) {
            $ntfsMsg = "Том создан недавно: $($volume.DriveLetter) - $($volumeAge.TotalHours) часов назад"
            $ntfsAnomalies += $ntfsMsg
            Add-Content $suspectLog $ntfsMsg
        }
    }
    
    # Анализ альтернативных потоков данных (ADS) - исправленная версия
    if ($volume.DriveLetter) {
        try {
            # Ограничиваем проверку только несколькими директориями верхнего уровня
            $dirsToCheck = @(
                "$($volume.DriveLetter)\Windows\System32",
                "$($volume.DriveLetter)\Program Files",
                "$($volume.DriveLetter)\Users\$env:USERNAME"
            )
            
            foreach ($dir in $dirsToCheck) {
                if (Test-Path $dir) {
                    # Проверяем только сами директории, не рекурсивно
                    $item = Get-Item -Path $dir -Force -ErrorAction SilentlyContinue
                    if ($item) {
                        $streams = Get-Item -Path $item.FullName -Stream * -ErrorAction SilentlyContinue 2>$null | 
                                  Where-Object { $_.Stream -ne ':$DATA' }
                        
                        if ($streams) {
                            $adsMsg = "Обнаружены альтернативные потоки данных в: $dir"
                            $ntfsAnomalies += $adsMsg
                            Add-Content $suspectLog $adsMsg
                            break # Прерываем после первого найденного
                        }
                    }
                }
            }
        } catch {
            # Игнорируем ошибки доступа
        }
    }
}

# ========== Проверка подозрительных процессов ==========
Write-Host "Поиск подозрительных процессов..." -ForegroundColor Cyan

$suspectProcessNames = @("spoofer", "hwid", "changer", "loader", "cloner", "volid", "biospatch", 
                        "uefi", "flashpatch", "chipsec", "mapper", "injector", "bypass")

$suspiciousProcesses = @()
$processes = Get-Process

foreach ($proc in $processes) {
    try {
        $procName = $proc.ProcessName.ToLower()
        $procPath = $proc.Path
        
        # Проверка имени процесса
        foreach ($suspect in $suspectProcessNames) {
            if ($procName -match $suspect) {
                $procMsg = "Подозрительный процесс: $($proc.ProcessName) (PID: $($proc.Id))"
                if ($procPath) {
                    $procMsg += " - Путь: $procPath"
                }
                $suspiciousProcesses += $procMsg
                Add-Content $suspectLog $procMsg
                break
            }
        }
        
        # Проверка на запуск из временных директорий
        if ($procPath) {
            if ($procPath -match "\\Temp\\" -or $procPath -match "\\tmp\\" -or 
                $procPath -match "\\AppData\\Local\\Temp\\") {
                $procMsg = "Процесс запущен из временной директории: $($proc.ProcessName) - $procPath"
                $suspiciousProcesses += $procMsg
                Add-Content $suspectLog $procMsg
            }
        }
    } catch {
        # Игнорируем процессы, к которым нет доступа
    }
}

# ========== Проверка служб ==========
Write-Host "Проверка подозрительных служб..." -ForegroundColor Cyan

$suspiciousServices = @()
$services = Get-CimInstance Win32_Service

foreach ($service in $services) {
    $serviceName = $service.Name.ToLower()
    # Проверка на скрытые или подозрительные службы
    if ($service.PathName) {
        $servicePath = $service.PathName -replace '"', ''
        
        # Проверка на выполнение из временных папок
        if ($servicePath -match 'temp|tmp|appdata\\local\\temp|programdata' -and 
            $servicePath -notmatch 'windows\\temp') {
            $svcMsg = "[SUSPICIOUS SERVICE] $($service.Name) - $($service.PathName)"
            $suspiciousServices += $svcMsg
            Add-Content $suspectLog $svcMsg
        }
        
        # Проверка на подозрительные имена
        if ($serviceName -match 'svchost|system|windows|update|defender|security' -and
            $service.PathName -notmatch 'windows\\system32|windows\\syswow64') {
            $svcMsg = "[FAKE SYSTEM SERVICE] $($service.Name) - $($service.PathName)"
            $suspiciousServices += $svcMsg
            Add-Content $suspectLog $svcMsg
        }
    }
}

# ========== Проверка сетевых подключений ==========
Write-Host "Анализ сетевых подключений..." -ForegroundColor Cyan

$suspiciousConnections = @()
$connections = Get-NetTCPConnection -State Established,Listen -ErrorAction SilentlyContinue

foreach ($conn in $connections) {
    try {
        $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        
        # Проверка на подозрительные порты
        $suspiciousPorts = @(4444, 5555, 6666, 7777, 8888, 9999, 12345, 31337, 1337)
        
        if ($conn.LocalPort -in $suspiciousPorts -or $conn.RemotePort -in $suspiciousPorts) {
            $connMsg = "[SUSPICIOUS PORT] Process: $($process.Name) - Local: $($conn.LocalAddress):$($conn.LocalPort) - Remote: $($conn.RemoteAddress):$($conn.RemotePort)"
            $suspiciousConnections += $connMsg
            Add-Content $suspectLog $connMsg
        }
        
        # Проверка на подключения к внешним IP для системных процессов
        if ($process.Name -in @('svchost', 'lsass', 'csrss', 'winlogon') -and 
            $conn.RemoteAddress -ne '0.0.0.0' -and 
            $conn.RemoteAddress -ne '::' -and
            $conn.RemoteAddress -notmatch '^(127\.|::1|10\.|172\.16\.|192\.168\.)') {
            $connMsg = "[SYSTEM PROCESS EXTERNAL CONNECTION] $($process.Name) -> $($conn.RemoteAddress):$($conn.RemotePort)"
            $suspiciousConnections += $connMsg
            Add-Content $suspectLog $connMsg
        }
    } catch {
        # Игнорируем ошибки
    }
}

# ========== Проверка автозагрузки ==========
Write-Host "Проверка элементов автозагрузки..." -ForegroundColor Cyan

$suspiciousStartup = @()

# Проверка реестра автозагрузки
$startupPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)

foreach ($path in $startupPaths) {
    if (Test-Path $path) {
        $items = Get-ItemProperty $path -ErrorAction SilentlyContinue
        
        foreach ($prop in $items.PSObject.Properties) {
            if ($prop.Name -notmatch '^PS|^Path$') {
                $value = $prop.Value.ToLower()
                
                # Проверка на подозрительные пути
                if ($value -match 'temp|tmp|appdata\\roaming|programdata' -or
                    $value -match 'powershell|cmd\.exe|wscript|cscript|mshta') {
                    $startupMsg = "[SUSPICIOUS STARTUP] $path\$($prop.Name) - $($prop.Value)"
                    $suspiciousStartup += $startupMsg
                    Add-Content $suspectLog $startupMsg
                }
            }
        }
    }
}

# ========== Проверка запланированных задач ==========
Write-Host "Анализ запланированных задач..." -ForegroundColor Cyan

$suspiciousTasks = @()
$tasks = Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'}

foreach ($task in $tasks) {
    $taskInfo = Get-ScheduledTaskInfo $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
    
    if ($task.Actions) {
        foreach ($action in $task.Actions) {
            if ($action.Execute) {
                $execPath = $action.Execute.ToLower()
                
                # Проверка на подозрительные команды
                if ($execPath -match 'powershell|cmd|wscript|cscript|mshta|rundll32' -or
                    $execPath -match 'temp|tmp|appdata|programdata') {
                    
                    # Исключаем известные системные задачи
                    if ($task.TaskPath -notmatch 'Microsoft\\Windows') {
                        $taskMsg = "[SUSPICIOUS TASK] $($task.TaskPath)$($task.TaskName) - $($action.Execute) $($action.Arguments)"
                        $suspiciousTasks += $taskMsg
                        Add-Content $suspectLog $taskMsg
                    }
                }
            }
        }
    }
}
# Проверка существующих драйверов
Get-ChildItem "C:\Windows\System32\drivers\*.sys" | ForEach-Object {
    Check-DriverHash $_.FullName
}
# Функция для проверки цифровой подписи драйвера
function Check-DriverSignature {
    param ($driverPath)

    $certificates = Get-AuthenticodeSignature -FilePath $driverPath

    if ($certificates.Status -eq 'Valid') {
        Write-Host "[Подписан] Драйвер: $driverPath" -ForegroundColor Green
        return "Microsoft-подписан"
    } else {
        Write-Host "[Не подписан] Драйвер: $driverPath" -ForegroundColor Red
        return "Подозрительный"
    }
}

# Проверка подписей всех драйверов

$hybridAnalysisApiKey = "okb7duaid4d743f2lpcpjmph0412da4c516qm6qrf98c3374wcklqyd3e527c25d"
$malwarebytesApiKey = "9256034b-7967-4253-a5d9-260663e4fa4f"
$metaDefenderApiKey = "e62d8183f3211a0a4068c3bb7ea7210b"

function Check-DriverHashWithHybridAnalysis {
    param ([string]$filePath)
    if (-not (Test-Path $filePath)) { return "❌ Файл не найден" }
    try {
        $hash = Get-FileHash -Path $filePath -Algorithm SHA256
        $sha256 = $hash.Hash.ToLower()
        $headers = @{ "x-hybrid-analysis-api-key" = $hybridAnalysisApiKey }
        $url = "https://www.hybrid-analysis.com/api/v2/scan/hash/$sha256"
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
        if ($response.success) {
            switch ($response.data.status) {
                "clean" { return "🟢 Clean (Hybrid Analysis)" }
                "malicious" { return "🔴 Malicious (Hybrid Analysis)" }
                default { return "⚠️ Status unknown (Hybrid Analysis)" }
            }
        } else {
            return "⚠️ Ошибка Hybrid Analysis API: Не удалось получить данные"
        }
    } catch {
        return "⚠️ Ошибка Hybrid Analysis-запроса или проверки: $_"
    }
}

function Check-DriverHashWithMalwarebytes {
    param ([string]$filePath)
    if (-not (Test-Path $filePath)) { return "❌ Файл не найден" }
    try {
        $hash = Get-FileHash -Path $filePath -Algorithm SHA256
        $sha256 = $hash.Hash.ToLower()
        $headers = @{ "x-api-key" = $malwarebytesApiKey }
        $url = "https://api.malwarebytes.com/v1/scan/hash/$sha256"
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
        switch ($response.status) {
            "clean" { return "🟢 Clean (Malwarebytes)" }
            "malicious" { return "🔴 Malicious (Malwarebytes)" }
            default { return "⚠️ Status unknown (Malwarebytes)" }
        }
    } catch {
        return "⚠️ Ошибка Malwarebytes API: $_"
    }
}

function Check-DriverHashWithMetaDefender {
    param ([string]$filePath)
    if (-not (Test-Path $filePath)) { return "❌ Файл не найден" }
    try {
        $hash = Get-FileHash -Path $filePath -Algorithm SHA256
        $sha256 = $hash.Hash.ToLower()
        $headers = @{ "apikey" = $metaDefenderApiKey }
        $url = "https://api.metadefender.com/v4/hash/$sha256"
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
        switch ($response.scan_results.scan_all_result_a) {
            "Clean" { return "🟢 Clean (MetaDefender)" }
            "Infected" { return "🔴 Malicious (MetaDefender)" }
            default { return "⚠️ Status unknown (MetaDefender)" }
        }
    } catch {
        return "⚠️ Ошибка MetaDefender API: $_"
    }
}
Write-Output "🧠 Запуск продвинутых эвристик..."

# === DSE Bypass Detection ===
Write-Output "[DSE] Проверка состояния подписи драйверов..."
$bcdOutput = bcdedit /enum
if ($bcdOutput -match "testsigning.*Yes") {
    Add-Content $suspectLog "[!] DSE Bypass обнаружен: Testsigning включён"
}
if ($bcdOutput -match "nointegritychecks.*Yes") {
    Add-Content $suspectLog "[!] DSE Bypass обнаружен: Integrity Checks отключены"
}

# === ACPI / VM Detection ===
Write-Output "[ACPI] Анализ ACPI таблиц и VM признаков..."
$acpi = Get-WmiObject -Namespace "root\\ACPI" -Class "*"
foreach ($entry in $acpi) {
    if ($entry.PSComputerName -match "VBOX|VMWARE|QEMU|HYPER|KVM|XEN") {
        Add-Content $suspectLog "[!] Обнаружены ACPI признаки виртуальной машины: $($entry.PSComputerName)"
    }
}

# === CPU Timing Check ===
Write-Output "[Timing] Проверка таймингов CPU..."
$time = Measure-Command { for ($i=0; $i -lt 100000; $i++) { $null = $i * 2 } }
if ($time.TotalMilliseconds -lt 20) {
    Add-Content $suspectLog "[!] Подозрение на эмуляцию CPU (тайминг слишком быстрый: $($time.TotalMilliseconds) мс)"
}

# === TaskScheduler Heuristics ===
Write-Output "[Tasks] Анализ планировщика заданий..."
$tasks = schtasks /query /fo LIST /v
foreach ($line in $tasks) {
    if ($line -match "Microsoft") { continue }
    if ($line -match "Hidden|system32|AppData|Temp|\\\\Users\\\\") {
        Add-Content $suspectLog "[!] Подозрительное задание планировщика: $line"
    }
}

# === WMI Persistence Detection ===
Write-Output "[WMI] Анализ на скрытую персистентность WMI..."
$wmiBindings = Get-WmiObject -Namespace "root\\subscription" -Class __FilterToConsumerBinding
$wmiConsumers = Get-WmiObject -Namespace "root\\subscription" -Class __EventConsumer
foreach ($bind in $wmiBindings) {
    Add-Content $suspectLog "[!] WMI Binding обнаружен: $($bind.Consumer)"
}
foreach ($consumer in $wmiConsumers) {
    Add-Content $suspectLog "[!] WMI Consumer обнаружен: $($consumer.Name)"
}

# === Services Analysis ===
Write-Output "[Services] Анализ автозапущенных сервисов..."
Get-WmiObject Win32_Service | Where-Object {
    $_.StartMode -eq "Auto" -and $_.PathName -notlike "*Windows*" -and $_.State -eq "Running"
} | ForEach-Object {
    Add-Content $suspectLog "[!] Подозрительный автозапущенный сервис: $($_.Name) | $($_.PathName)"
}

# === Registry Autorun Analysis ===
Write-Output "[Registry] Анализ автозагрузки из реестра..."
$autorunPaths = @(
    "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM:\\System\\CurrentControlSet\\Services",
    "HKLM:\\Software\\Microsoft\\Active Setup\\Installed Components"
)
foreach ($path in $autorunPaths) {
    if (Test-Path $path) {
        Get-ItemProperty -Path $path | ForEach-Object {
            foreach ($property in $_.PSObject.Properties) {
                if ($property.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                    Add-Content $suspectLog "[!] Автозагрузка из ${path}: $($property.Name) = $($property.Value)"
                }
            }
        }
    }
}

$drivers = Get-ChildItem "C:\Windows\System32\drivers" -Filter "*.sys" -Recurse

foreach ($driver in $drivers) {
    $result = Check-DriverSignature $driver.FullName
    Add-Content $baseInfoLog "[Подпись драйвера] $($driver.FullName): $result"
}

#мониторинг драйверов + VirusTotal интеграция + хэш-чек

function Check-DriverHash($filePath) {
    $hash = Get-FileHash -Path $filePath -Algorithm SHA256
    $trusted = $trustedHashes | Where-Object { $_.SHA256 -eq $hash.Hash }
    
    if (-not $trusted) {
        Write-Warning "[!] Обнаружен неизвестный драйвер: $($filePath)"
        $headers = @{ "x-apikey" = $apiKey }
        try {
            $response = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$($hash.Hash)" -Headers $headers -Method GET
            if ($response.data.attributes.last_analysis_stats.malicious -gt 0) {
                Write-Host "    ⚠️ VirusTotal: MALICIOUS ($($response.data.attributes.last_analysis_stats.malicious))"
            } else {
                Write-Host "    ✔ VirusTotal: Clean" 
            }
        } catch {
            Write-Host "    ⚠️ Не удалось проверить в VirusTotal"
        }
    } else {
        Write-Host "[OK] Доверенный драйвер: $($filePath)"
    }
}

# ========== Проверка WMI ==========
Write-Host "Проверка WMI на наличие вредоносных объектов..." -ForegroundColor Cyan

$suspiciousWMI = @()

# Проверка WMI Event Consumers
try {
    $eventConsumers = Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
    
    foreach ($consumer in $eventConsumers) {
        if ($consumer.__CLASS -eq 'CommandLineEventConsumer') {
            $wmiMsg = "[WMI COMMANDLINE CONSUMER] Name: $($consumer.Name) - CommandLine: $($consumer.CommandLineTemplate)"
            $suspiciousWMI += $wmiMsg
            Add-Content $suspectLog $wmiMsg
        }
    }
} catch {
    # Игнорируем ошибки WMI
}
# Поиск процессов без физического файла (memory-only)
Get-Process | Where-Object {
    try { -not $_.Path } catch { $true }
} | ForEach-Object {
    Write-Host "Обнаружен процесс без дискового файла: $($_.ProcessName) (PID:$($_.Id))" -ForegroundColor Yellow
}

# ========== Проверка файловой системы ==========
Write-Host "Поиск подозрительных файлов..." -ForegroundColor Cyan

$suspiciousFiles = @()
$pathsToCheck = @(
    "$env:TEMP",
    "$env:APPDATA",
    "$env:LOCALAPPDATA\Temp",
    "$env:ProgramData"
)

$suspiciousExtensions = @('.ps1', '.bat', '.cmd', '.vbs', '.js', '.exe', '.dll', '.scr')

foreach ($path in $pathsToCheck) {
    if (Test-Path $path) {
        try {
            $files = Get-ChildItem -Path $path -File -Recurse -ErrorAction SilentlyContinue | 
                     Where-Object { $_.Extension -in $suspiciousExtensions -and $_.CreationTime -gt (Get-Date).AddDays(-7) }
            
            foreach ($file in $files) {
                # Проверка на скрытые файлы
                if ($file.Attributes -band [System.IO.FileAttributes]::Hidden) {
                    $fileMsg = "[HIDDEN FILE] $($file.FullName) - Created: $($file.CreationTime)"
                    $suspiciousFiles += $fileMsg
                    Add-Content $suspectLog $fileMsg
                }
                
                # Проверка на файлы с двойным расширением
                if ($file.Name -match '\.(jpg|jpeg|png|doc|pdf|txt)\.(exe|scr|bat|cmd|ps1)$') {
                    $fileMsg = "[DOUBLE EXTENSION] $($file.FullName)"
                    $suspiciousFiles += $fileMsg
                    Add-Content $suspectLog $fileMsg
                }
            }
        } catch {
            # Игнорируем недоступные папки
        }
    }
}
# Итоговая оценка для каждого драйвера
function Generate-DriverAssessment {
    param ($driverPath)

    $signatureResult = Check-DriverSignature $driverPath
    $vtResult = Check-DriverHashWithVirusTotal $driverPath

    # Оценка на основе подписей и VirusTotal
    if ($signatureResult -eq "Microsoft-подписан" -and $vtResult -eq "VT Clean") {
        return "Microsoft-подписан, VT Clean"
    } elseif ($signatureResult -eq "Microsoft-подписан" -and $vtResult -eq "Подозрительный") {
        return "Microsoft-подписан, Подозрительный"
    } elseif ($signatureResult -eq "Подозрительный") {
        return "Подозрительный"
    } else {
        return "Не проверено"
    }
}

# Применяем итоговую оценку
foreach ($driver in $drivers) {
    $assessment = Generate-DriverAssessment $driver.FullName
    Add-Content $baseInfoLog "[Оценка драйвера] $($driver.FullName): $assessment"
}
# ========== Генерация отчета ==========
Write-Host "`nГенерация итогового отчета..." -ForegroundColor Yellow

$report = @"
========================================
   ОТЧЕТ О БЕЗОПАСНОСТИ СИСТЕМЫ
========================================
Дата проверки: $(Get-Date -Format "dd.MM.yyyy HH:mm:ss")
Имя компьютера: $env:COMPUTERNAME
Пользователь: $env:USERNAME

========================================
СВОДКА РЕЗУЛЬТАТОВ:
========================================
Подозрительные процессы: $($suspiciousProcesses.Count)
Подозрительные службы: $($suspiciousServices.Count)
Подозрительные сетевые подключения: $($suspiciousConnections.Count)
Подозрительные элементы автозагрузки: $($suspiciousStartup.Count)
Подозрительные запланированные задачи: $($suspiciousTasks.Count)
Подозрительные WMI объекты: $($suspiciousWMI.Count)
Подозрительные файлы: $($suspiciousFiles.Count)

"@

Add-Content $reportFile $report

# Вывод результатов
if ($suspiciousProcesses.Count -gt 0) {
    Add-Content $reportFile "`n=== ПОДОЗРИТЕЛЬНЫЕ ПРОЦЕССЫ ==="
    $suspiciousProcesses | ForEach-Object { Add-Content $reportFile $_ }
}

if ($suspiciousServices.Count -gt 0) {
    Add-Content $reportFile "`n=== ПОДОЗРИТЕЛЬНЫЕ СЛУЖБЫ ==="
    $suspiciousServices | ForEach-Object { Add-Content $reportFile $_ }
}

if ($suspiciousConnections.Count -gt 0) {
    Add-Content $reportFile "`n=== ПОДОЗРИТЕЛЬНЫЕ СЕТЕВЫЕ ПОДКЛЮЧЕНИЯ ==="
    $suspiciousConnections | ForEach-Object { Add-Content $reportFile $_ }
}

if ($suspiciousStartup.Count -gt 0) {
    Add-Content $reportFile "`n=== ПОДОЗРИТЕЛЬНЫЕ ЭЛЕМЕНТЫ АВТОЗАГРУЗКИ ==="
    $suspiciousStartup | ForEach-Object { Add-Content $reportFile $_ }
}

if ($suspiciousTasks.Count -gt 0) {
    Add-Content $reportFile "`n=== ПОДОЗРИТЕЛЬНЫЕ ЗАПЛАНИРОВАННЫЕ ЗАДАЧИ ==="
    $suspiciousTasks | ForEach-Object { Add-Content $reportFile $_ }
}

if ($suspiciousWMI.Count -gt 0) {
    Add-Content $reportFile "`n=== ПОДОЗРИТЕЛЬНЫЕ WMI ОБЪЕКТЫ ==="
    $suspiciousWMI | ForEach-Object { Add-Content $reportFile $_ }
}

if ($suspiciousFiles.Count -gt 0) {
    Add-Content $reportFile "`n=== ПОДОЗРИТЕЛЬНЫЕ ФАЙЛЫ ==="
    $suspiciousFiles | ForEach-Object { Add-Content $reportFile $_ }
}

# ========== Рекомендации ==========
$recommendations = @"

========================================
РЕКОМЕНДАЦИИ ПО БЕЗОПАСНОСТИ:
========================================
1. Внимательно изучите все обнаруженные подозрительные элементы
2. Проверьте неизвестные процессы на VirusTotal.com
3. Отключите подозрительные службы и элементы автозагрузки
4. Просканируйте систему актуальным антивирусом
5. Обновите операционную систему и все программы
6. Измените пароли после очистки системы
7. Включите брандмауэр Windows и антивирус
8. Регулярно делайте резервные копии важных данных
"@

Add-Content $reportFile $recommendations

# Вывод итогов
Write-Host "`n========== АНАЛИЗ ЗАВЕРШЕН ==========" -ForegroundColor Green
Write-Host "Отчет сохранен в: $reportFile" -ForegroundColor Yellow
Write-Host "Подозрительные элементы: $suspectLog" -ForegroundColor Yellow

$totalSuspicious = $suspiciousProcesses.Count + $suspiciousServices.Count + 
                  $suspiciousConnections.Count + $suspiciousStartup.Count + 
                  $suspiciousTasks.Count + $suspiciousWMI.Count + $suspiciousFiles.Count

if ($totalSuspicious -gt 0) {
    Write-Host "`nВНИМАНИЕ! Обнаружено подозрительных элементов: $totalSuspicious" -ForegroundColor Red
    Write-Host "Рекомендуется дополнительная проверка системы!" -ForegroundColor Red
} else {
    Write-Host "`nСистема выглядит чистой. Подозрительных элементов не обнаружено." -ForegroundColor Green
}

Read-Host "Нажмите Enter для выхода..."