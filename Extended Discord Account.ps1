# Extended Discord Account Artifact Scanner
# Ищет почты, ники и Discord ID в LevelDB Discord + популярных браузеров
# Токены игнорируются

$ErrorActionPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest

$outFile = Join-Path $env:USERPROFILE "Desktop\DiscordAccountArtifacts.csv"
$results = New-Object System.Collections.Generic.List[object]

$paths = @(
    "$env:AppData\Discord\Local Storage\leveldb",
    "$env:LocalAppData\Discord\Local Storage\leveldb",
    "$env:AppData\discordptb\Local Storage\leveldb",
    "$env:AppData\discordcanary\Local Storage\leveldb",

    "$env:LocalAppData\Google\Chrome\User Data\*\Local Storage\leveldb",
    "$env:LocalAppData\Microsoft\Edge\User Data\*\Local Storage\leveldb",
    "$env:LocalAppData\BraveSoftware\Brave-Browser\User Data\*\Local Storage\leveldb",
    "$env:AppData\Opera Software\Opera Stable\Local Storage\leveldb",
    "$env:AppData\Opera Software\Opera GX Stable\Local Storage\leveldb",

    "$env:AppData\Mozilla\Firefox\Profiles"
) | Where-Object { Test-Path $_ }

$rxEmail      = [regex]'(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b'
$rxUserTag    = [regex]'\b[\w.\-]{2,32}#\d{4}\b'
$rxJSONUser   = [regex]'(?i)"username"\s*:\s*"([^"\\]{2,32})"'
$rxSnowflake  = [regex]'\b\d{17,19}\b'
$rxToken1     = [regex]'(?i)\bmfa\.[A-Za-z0-9_\-]{80,}\b'
$rxToken2     = [regex]'\b[A-Za-z0-9_\-]{24}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}\b'

function Get-PrintableStrings {
    param([byte[]]$Bytes, [int]$MinLen = 4)
    $sb = New-Object System.Text.StringBuilder
    $strings = New-Object System.Collections.Generic.List[string]
    foreach ($b in $Bytes) {
        if ($b -ge 0x20 -and $b -le 0x7E) {
            [void]$sb.Append([char]$b)
        } else {
            if ($sb.Length -ge $MinLen) { $strings.Add($sb.ToString()) }
            $sb.Clear() | Out-Null
        }
    }
    if ($sb.Length -ge $MinLen) { $strings.Add($sb.ToString()) }
    return $strings
}

function Scan-File {
    param([string]$Path)
    try { $bytes = [System.IO.File]::ReadAllBytes($Path) } catch { return }
    $textChunks = Get-PrintableStrings -Bytes $bytes -MinLen 4

    foreach ($chunk in $textChunks) {
        if ($rxToken1.IsMatch($chunk) -or $rxToken2.IsMatch($chunk)) { continue }

        foreach ($m in $rxEmail.Matches($chunk)) {
            $results.Add([pscustomobject]@{SourceFile=$Path; Type='email'; Value=$m.Value })
        }
        foreach ($m in $rxUserTag.Matches($chunk)) {
            $results.Add([pscustomobject]@{SourceFile=$Path; Type='username_tag'; Value=$m.Value })
        }
        foreach ($m in $rxJSONUser.Matches($chunk)) {
            $results.Add([pscustomobject]@{SourceFile=$Path; Type='username'; Value=$m.Groups[1].Value })
        }
        foreach ($m in $rxSnowflake.Matches($chunk)) {
            if ($m.Value.Length -ge 17 -and $m.Value.Length -le 19) {
                $results.Add([pscustomobject]@{SourceFile=$Path; Type='discord_id'; Value=$m.Value })
            }
        }
    }
}

Write-Host "== Сканирование LevelDB ==" -ForegroundColor Cyan
foreach ($p in $paths) {
    Write-Host "Сканирую: $p"
    Get-ChildItem -LiteralPath $p -Recurse -Include *.log,*.ldb -File -ErrorAction SilentlyContinue | ForEach-Object {
        Scan-File -Path $_.FullName
    }
}

$ffProfiles = Get-ChildItem "$env:AppData\Mozilla\Firefox\Profiles" -Directory -ErrorAction SilentlyContinue
foreach ($prof in $ffProfiles) {
    $ffLevel = Join-Path $prof.FullName "storage\default"
    if (Test-Path $ffLevel) {
        Write-Host "Сканирую Firefox storage: $ffLevel"
        Get-ChildItem $ffLevel -Recurse -Include *.log,*.ldb -File -ErrorAction SilentlyContinue | ForEach-Object {
            Scan-File -Path $_.FullName
        }
    }
}

$results = $results | Sort-Object SourceFile,Type,Value -Unique

if ($results.Count -eq 0) {
    Write-Warning "Ничего не найдено."
} else {
    $results | Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8
    Write-Host "`nГотово! Найдено записей: $($results.Count)" -ForegroundColor Green
    Write-Host "Файл сохранён: $outFile"
    try { Invoke-Item $outFile } catch {}
}
