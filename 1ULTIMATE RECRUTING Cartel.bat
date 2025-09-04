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
set "TRIGGERS=htc corsair liit f9d89253df0005cbb37e cae57b53a71837460bf3 0f98c6ec7af1bd42e4c1 bc3fc101c69154b64b6c 8cd0b4df17fa01696737 b198b7c86ead8b11ce90 2ec33a42219c46764ee2 loader 38783627b47b692b5015 d067b645af5873259683 aae0755dfb25bd6588dd f0d2e3535d53d000c79a ccc21af01df8188d4439 725f98a54b213ba55ef3 ba6945d94f1c8b29bef0 544628d5423bb99f5b4a 7e28300f1a7e048b19de 208731ecdc23d10ebb51 13c9d5e27afa912ed986 0305a01d617f4ee09efb HitVPN 01b27ef4c8acec59176f 00f5ae3b023b7c97707a ab495a038fca890d939e a637b61d3682c59774a8 2aee7d2224494fc47f17 d35c84b31e2e50cb7a87 c8620480ec15ba87e6f6 e5510b54f7adf5b64ef1 440fea17c26a4ccbc6a8 a974f00902f5caafa4d9 5ddbadd2284713ea8e9b ab96230e7c5b791ff04c 737c69f3aca9f3041d78 98884745a356b2c12feb 6e2f198c279b20002bc58d42b52330c8084fc0487c19af41d13e00e00fdd3b0d 3274bbb21a4d177ee50d 7ad9c7021c0c41b82f68 infected c655bbb7a8ad33599435 74688fa760133e0c60b7 8c730dbd32a86f9f9631 46aa29ea97d7fa940422 fd320c5bf5d436040550 0627359db673b9fdbe8f 17d38bb3b00d224dd001 ebecdc8466f29aa94104 907e07a3f7621f53cbb5 765b9e706c65c4b9af3d 58304187b8576d32f959 bf3722cdc039c464bb31 a634ac5dd64d928f34eb 38efcd71f34dfefbbb1d crdownload 83960635aba8123b73a8 26b9d28bb0c93e47c22e 654f179b1c4c79fe546d 7117de7a33342707d973 11d867cf1ca607002c68 02b7898c2e6250e32e6f b19d1636ae870a719052 ef97333aa9c92e4adb56 6598920331430bec33ff build infected fsle steam ReShade_Setup_ Unitheft executable bound Injector  cheat build unicor reshade A1 inj ExtremeInjectorv3 Injector Niepotwierdzony  Injector discord chtobi nebilo nvidiaProfileInspector  اضافة ملفات الكسر Unconfirmed program Unconfirmed 446999 software file  Nonconfermato CanKilmer csgo DC31 h  DDG U  الي بيشغل ابو عبداله Nicht bestätigt meQrWMb NIGHTFALL 9HezYa YvkTfojpp3 dNzJr6OKaQ 8JM4PyYZ zJqZ9pm8 MDUvaDJwI eKH6t UTCcV G4RUB6G1p launcher jh8oXPi8A jPVWfLp kb7ApDZl TRIGGERS AUTO-LUT build build[1] fsle steam build ReShade_Setup_5.0.2 Unitheft executable bound DEMORGAN-SHVEIKA DEMORGAN-TOKARKA FARM-COW FAST-RELOG FRUIT-SALAT GYM KPK-TAXI LOTEREYA MAC-CHEESE PORT PORT-RUN RAGU RUN SHAHTA SMUZI STROIKA TRIGGER altv_launcher bulid_1 uniloader nokia 0x.exe unicore leet vanish cheat Tor_B not defined liit loader TRIGGERS AUTO-LUT build build[1] fsle steam build ReShade_Setup_5.0.2 Unitheft executable bound DEMORGAN-SHVEIKA DEMORGAN-TOKARKA FARM-COW FAST-RELOG FRUIT-SALAT GYM KPK-TAXI LOTEREYA MAC-CHEESE PORT PORT-RUN RAGU RUN SHAHTA SMUZI STROIKA TRIGGER altv_launcher bulid_1 uniloader nokia 0x.exe unicore leet vanish cheat Tor_B"
echo Поиск файлов, содержащих ключевые слова...
for %%K in (%TRIGGERS%) do (
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