@echo off
chcp 65001 >nul

:: == Логотип ==
echo   ██████╗ █████╗ ██████╗ ████████╗███████╗██╗     
echo  ██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██║     
echo  ██║     ███████║██████╔╝   ██║   █████╗  ██║     
echo  ██║     ██╔══██║██╔══██╗   ██║   ██╔══╝  ██║     
echo  ╚██████╗██║  ██║██║  ██║   ██║   ███████╗███████╗
echo   ╚═════╝╚═╝  ╚═╝  ╚═╝  ╚═╝   ╚══════╝╚══════╝
echo.         ULTIMATE RECRUTING v3.5 (Fixed)
echo.                  by xattab
echo -----------------------------------------------
echo.
color 0B
:: == Создание папки для логов рядом с батником ==
set "logdir=%~dp0LOGS_CARTEL"
if not exist "%logdir%" mkdir "%logdir%"

:: == Открытие нужных папок ==
start "" %windir%\Prefetch
start "" %appdata%\Microsoft\Windows\Recent
start "" %temp%
start "" %appdata%
if exist "C:\ReportArchive" start "" "C:\ReportArchive"

REM --- Дополнительные полезные папки ---
start "" "%localappdata%\Temp"
start "" "%localappdata%"
start "" "%userprofile%\Downloads"
start "" "%userprofile%\Documents"
start "" "%programdata%"
start "" "%systemroot%\Temp"
start "" "%userprofile%\AppData\Local\Microsoft\Windows\WER\ReportArchive"
start "" "%userprofile%\AppData\Local\Microsoft\Windows\WER\ReportQueue"
start "" "%userprofile%\AppData\Local\CrashDumps"
start "" "%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
start "" "%userprofile%\AppData\Local\Microsoft"
start "" "%userprofile%\AppData\Roaming\Microsoft"
start "" "%systemroot%\System32\drivers"
start "" "%programfiles%"
start "" "%programfiles(x86)%"
start "" "%userprofile%\AppData\Roaming\Discord\Cache"
start "" "%userprofile%\AppData\Roaming\Telegram Desktop\tdata"
start "" "%localappdata%\Google\Chrome\User Data\Default\Cache"
start "" "%appdata%\Mozilla\Firefox\Profiles"
start "" "%appdata%\Opera Software\Opera Stable"
start "" "%userprofile%\AppData\Local\Packages"
start "" C:\Windows\System32\drivers\etc

:: == Переход на сайты ==
start "" https://0xcheats.net/auth/forgot/
start "" https://leet-cheats.ru/restore_password
start "" https://unicore.cloud/forum/lost-password/
start "" https://vanish-cheat.com/login 
start "" https://oplata.info/info/
start "" https://funpay.com/account/login
start "" https://forum.majestic-rp.ru/
start "" https://discord.com/
start "" https://myactivity.google.com/myactivity?hl=ru&pli=1&q=cheat
start "" https://www.youtube.com/watch?v=uDYOP3oyWzQ
start "" https://www.youtube.com/@silhouette69mj
start "" https://echo.ac/free
start "" https://youtu.be/AQ8ul7SzV_4 
start "" https://astra.rip/products
start "" https://nfcheats.com/profile
start "" https://hydrogen.ac/
start "" https://nixware.cc/
start "" https://ret9.fun/
start "" https://skript.gg/

echo.
:: == Окно с системной информацией ==
start cmd /k systeminfo

:: == Получение всех локальных дисков ==
setlocal enabledelayedexpansion
set "drives="
for %%d in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    if exist "%%d:\" set "drives=!drives! %%d:"
)

:: == Поиск файлов по расширениям и запись путей в логи по всем дискам ==
echo Поиск файлов по всем дискам: %drives%
for %%d in (%drives%) do (
    echo --- Поиск .ahk на диске %%d ---
    dir /b /s /a-d "%%d\*.ahk" 2>nul >> "%logdir%\ahk_files.log"
    echo --- Поиск .exe на диске %%d ---
    dir /b /s /a-d "%%d\*.exe" 2>nul >> "%logdir%\exe_files.log"
    echo --- Поиск .zip на диске %%d ---
    dir /b /s /a-d "%%d\*.zip" 2>nul >> "%logdir%\zip_files.log"
    echo --- Поиск .rar на диске %%d ---
    dir /b /s /a-d "%%d\*.rar" 2>nul >> "%logdir%\rar_files.log"
)

:: == Поиск по ключам с раздельными логами ==
echo Поиск файлов, содержащих ключевые слова...
for /f %%K in (triggers.txt) do (
    echo ***** Найдено по ключу: %%K *****
    for %%d in (%drives%) do (
        dir /b /s /a-d "%%d:\*%%K*" 2>nul >> "%logdir%\search_%%K.log"
    )
)
echo ===== Поиск завершён. =====
echo Все логи и результаты - в папке LOGS_CARTEL

:: == Автоматическое открытие истории браузеров (если установлен браузер) ==
rem Chrome
if exist "%localappdata%\Google\Chrome\Application\chrome.exe" (
    start "" "chrome.exe" "chrome://history/"
)
rem Edge
if exist "%localappdata%\Microsoft\Edge\Application\msedge.exe" (
    start "" "msedge.exe" "edge://history/"
)
rem Yandex
if exist "%localappdata%\Yandex\YandexBrowser\Application\browser.exe" (
    start "" "browser.exe" "browser://history/"
)
rem Opera (Opera GX и обычный)
if exist "%localappdata%\Programs\Opera\launcher.exe" (
    start "" "%localappdata%\Programs\Opera\launcher.exe" "opera://history/"
)
if exist "%localappdata%\Programs\Opera GX\launcher.exe" (
    start "" "%localappdata%\Programs\Opera GX\launcher.exe" "opera://history/"
)
rem Firefox (нельзя открыть прямой URL истории)
if exist "%programfiles%\Mozilla Firefox\firefox.exe" (
    start "" "%programfiles%\Mozilla Firefox\firefox.exe"
    echo Откройте меню Firefox → Библиотека → Журнал
)
rem Internet Explorer (нет прямой истории, только вручную)
if exist "%programfiles%\Internet Explorer\iexplore.exe" (
    start explorer.exe shell:history
    echo История Explorer открыта через Проводник (shell:history)
)

echo === Готово. Смотреть папку LOGS_CARTEL. Браузеры открыты, проверьте вкладки. ===
pause
exit /b