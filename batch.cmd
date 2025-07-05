@echo off
:: =============================================================
::  PC Tweaker by eulfen
::  https://github.com/eulfen | @eulfen
::  Copyright (c) 2024 eulfen. All rights reserved.
::  Credit required for redistribution or modification.
:: =============================================================

::  Enhanced Windows 10/11 Optimization Script
::  Author: eulfen | https://github.com/eulfen | @eulfen
:: =============================================================

:: AUTHORSHIP SPLASH (DO NOT REMOVE)
echo.
echo  =============================================================
echo  =================== TWEAKED BY EULFEN =======================
echo  =============================================================
echo.
echo                 Respect the author. Improve responsibly.
echo.
:: Centered splash (console width 70-80 chars)
timeout /t 3 >nul

:: =========================
:: 0. UAC AUTO-ELEVATION & ENVIRONMENT
:: =========================

:: Auto-elevate if not running as admin
openfiles >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Requesting admin rights...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Set backup and log folder
set "BACKUP_DIR=%SystemDrive%\PC_Tweaker_Backups"
if not exist "%BACKUP_DIR%" mkdir "%BACKUP_DIR%"
set "LOG=%BACKUP_DIR%\TweakerLog.txt"

:: Logging function
setlocal EnableDelayedExpansion
set "ts="
for /f "tokens=1-2 delims= " %%a in ('wmic os get localdatetime ^| find "."') do set "ts=%%a"
set "ts=!ts:~0,4!-!ts:~4,2!-!ts:~6,2! !ts:~8,2!:!ts:~10,2!:!ts:~12,2!"
endlocal & set "ts=%ts%"
echo [%ts%] Script started >> "%LOG%"

:: =========================
:: 0.1 RESTORE MODE
:: =========================
if /i "%~1"=="/restore" (
    echo [*] Restoring registry backups...
    for %%R in ("%BACKUP_DIR%\*.reg") do (
        reg import "%%R" >> "%LOG%" 2>&1
        echo [*] Restored %%~nxR >> "%LOG%"
    )
    echo [*] Restore complete. >> "%LOG%"
    pause
    exit /b 0
)

:: =========================
:: AUTHORSHIP WATERMARK (DO NOT REMOVE)
:: =========================
reg add "HKCU\Software\eulfenTweaker" /v Signature /t REG_SZ /d "Optimized by eulfen - PC Tweaker v1" /f >nul 2>&1

:: =========================
:: 1. DEBLOAT APPS & SERVICES
:: =========================
:Debloat
echo [*] Debloating unnecessary apps...
echo [%date% %time%] Debloat started >> "%LOG%"

:: Remove safe bloatware
powershell -Command "Get-AppxPackage *xbox* | Remove-AppxPackage -ErrorAction SilentlyContinue" >nul 2>&1
powershell -Command "Get-AppxPackage *ZuneMusic* | Remove-AppxPackage -ErrorAction SilentlyContinue" >nul 2>&1
powershell -Command "Get-AppxPackage *ZuneVideo* | Remove-AppxPackage -ErrorAction SilentlyContinue" >nul 2>&1
powershell -Command "Get-AppxPackage *bing* | Remove-AppxPackage -ErrorAction SilentlyContinue" >nul 2>&1
powershell -Command "Get-AppxPackage *solitaire* | Remove-AppxPackage -ErrorAction SilentlyContinue" >nul 2>&1
powershell -Command "Get-AppxPackage *candycrush* | Remove-AppxPackage -ErrorAction SilentlyContinue" >nul 2>&1
powershell -Command "Get-AppxPackage *skypeapp* | Remove-AppxPackage -ErrorAction SilentlyContinue" >nul 2>&1
powershell -Command "Get-AppxPackage *getstarted* | Remove-AppxPackage -ErrorAction SilentlyContinue" >nul 2>&1
powershell -Command "Get-AppxPackage *3dbuilder* | Remove-AppxPackage -ErrorAction SilentlyContinue" >nul 2>&1
powershell -Command "Get-AppxPackage *onenote* | Remove-AppxPackage -ErrorAction SilentlyContinue" >nul 2>&1
powershell -Command "Get-AppxPackage *cortana* | Remove-AppxPackage -ErrorAction SilentlyContinue" >nul 2>&1
powershell -Command "Get-AppxPackage *officehub* | Remove-AppxPackage -ErrorAction SilentlyContinue" >nul 2>&1
powershell -Command "Get-AppxPackage *people* | Remove-AppxPackage -ErrorAction SilentlyContinue" >nul 2>&1
powershell -Command "Get-AppxPackage *yourphone* | Remove-AppxPackage -ErrorAction SilentlyContinue" >nul 2>&1
powershell -Command "Get-AppxPackage *mixedreality* | Remove-AppxPackage -ErrorAction SilentlyContinue" >nul 2>&1
powershell -Command "Get-AppxPackage *oneconnect* | Remove-AppxPackage -ErrorAction SilentlyContinue" >nul 2>&1
powershell -Command "Get-AppxPackage *print3d* | Remove-AppxPackage -ErrorAction SilentlyContinue" >nul 2>&1
powershell -Command "Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage -ErrorAction SilentlyContinue" >nul 2>&1
:: Do NOT remove Microsoft Store, Defender, or Windows Update

:: Disable Xbox services
sc stop XblAuthManager >nul 2>&1
sc config XblAuthManager start= disabled >nul 2>&1
sc stop XblGameSave >nul 2>&1
sc config XblGameSave start= disabled >nul 2>&1
sc stop XboxNetApiSvc >nul 2>&1
sc config XboxNetApiSvc start= disabled >nul 2>&1

:: =========================
:: 2. PERFORMANCE TWEAKS
:: =========================
:Optimize
echo [*] Applying system performance tweaks...
echo [%date% %time%] Optimize started >> "%LOG%"

:: Backup registry keys before editing
reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" "%BACKUP_DIR%\VisualEffects.reg" /y >nul 2>&1
reg export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "%BACKUP_DIR%\MemoryManagement.reg" /y >nul 2>&1

:: Set visual effects to performance
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewAlphaSelect /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAnimations /t REG_DWORD /d 0 /f >nul 2>&1

:: Disable hibernation (frees disk space)
powercfg -h off >nul 2>&1

:: Set system to best performance (Processor scheduling)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 26 /f >nul 2>&1

:: =========================
:: 3. NETWORK & BOOT OPTIMIZATION
:: =========================
:Network
echo [*] Optimizing network and boot...
echo [%date% %time%] Network started >> "%LOG%"

:: Backup TCP/IP parameters
reg export "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "%BACKUP_DIR%\TcpipParameters.reg" /y >nul 2>&1

:: TCP/IP tweaks
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpAckFrequency /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpNoDelay /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v MaxUserPort /t REG_DWORD /d 65534 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpTimedWaitDelay /t REG_DWORD /d 30 /f >nul 2>&1

:: Enable Fast Boot (if available)
powercfg /hibernate on >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 1 /f >nul 2>&1

:: =========================
:: 4. CLEAN TEMP & CACHE FILES
:: =========================
:Clean
echo [*] Cleaning up temporary and cache files...
echo [%date% %time%] Clean started >> "%LOG%"

:: Clean user and system temp
del /s /f /q "%TEMP%\*" >nul 2>&1
del /s /f /q "%SystemRoot%\Temp\*" >nul 2>&1

:: Clean prefetch
del /s /f /q "%SystemRoot%\Prefetch\*" >nul 2>&1

:: Clean Windows Update cache (safe)
net stop wuauserv >nul 2>&1
del /s /f /q "%SystemRoot%\SoftwareDistribution\Download\*" >nul 2>&1
net start wuauserv >nul 2>&1

:: Clean Windows Error Reporting
del /s /f /q "%SystemRoot%\System32\winevt\Logs\*" >nul 2>&1

:: --- NEW: Cleanmgr, DNS, Event Logs, Store Cache ---
:: Run Cleanmgr silently (system cleanup)
cleanmgr /sagerun:1 >nul 2>&1

:: Clear DNS cache
ipconfig /flushdns >nul 2>&1

:: Clear all Windows Event Viewer logs
for /f "tokens=*" %%l in ('wevtutil el') do wevtutil cl "%%l" >nul 2>&1

:: Clear Microsoft Store cache
wsreset.exe >nul 2>&1

:: =========================
:: 5. DISABLE TELEMETRY & BACKGROUND TASKS
:: =========================
:Telemetry
echo [*] Disabling telemetry and unnecessary background tasks...
echo [%date% %time%] Telemetry started >> "%LOG%"

:: Backup relevant registry keys
reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "%BACKUP_DIR%\DataCollection.reg" /y >nul 2>&1

:: Disable telemetry via registry
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f >nul 2>&1

:: Disable DiagTrack service
sc stop DiagTrack >nul 2>&1
sc config DiagTrack start= disabled >nul 2>&1

:: Disable telemetry scheduled tasks
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable >nul 2>&1

:: --- NEW: Disable Delivery Optimization ---
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f >nul 2>&1

:: =========================
:: 6. UI RESPONSIVENESS & LATENCY
:: =========================
:UI
echo [*] Improving UI responsiveness...
echo [%date% %time%] UI started >> "%LOG%"

:: Disable menu show delay
reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d 0 /f >nul 2>&1

:: Disable animations
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAnimations /t REG_DWORD /d 0 /f >nul 2>&1

:: =========================
:: 7. POWER PLAN
:: =========================
:Power
echo [*] Setting power plan to Ultimate Performance (if available)...
echo [%date% %time%] Power started >> "%LOG%"

:: Enable Ultimate Performance power plan (Win10/11 Pro/Workstation)
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 >nul 2>&1
powercfg -setactive e9a42b02-d5df-448d-aa00-03f14749eb61 >nul 2>&1

:: --- NEW: Disable USB power saving ---
for /f "tokens=*" %%u in ('wmic path Win32_USBHub get DeviceID ^| find "\"') do (
    powercfg -setacvalueindex SCHEME_CURRENT SUB_USB USBSELECTIVE SUSPEND 0 >nul 2>&1
    powercfg -setdcvalueindex SCHEME_CURRENT SUB_USB USBSELECTIVE SUSPEND 0 >nul 2>&1
)
powercfg -SetActive SCHEME_CURRENT >nul 2>&1

:: =========================
:: 8. DISABLE UNNECESSARY STARTUP ENTRIES
:: =========================
:Startup
echo [*] Disabling unnecessary startup entries...
echo [%date% %time%] Startup started >> "%LOG%"

:: Disable OneDrive auto-start (do not uninstall)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDrive /t REG_SZ /d "" /f >nul 2>&1

:: =========================
:: 9. DISABLE UNNECESSARY SERVICES
:: =========================
:Services
echo [*] Disabling unnecessary services...
echo [%date% %time%] Services started >> "%LOG%"

:: Disable SysMain (Superfetch)
sc stop SysMain >nul 2>&1
sc config SysMain start= disabled >nul 2>&1

:: Disable Windows Search (optional, disables indexing - comment out if you use search a lot)
:: sc stop "WSearch" >nul 2>&1
:: sc config "WSearch" start= disabled >nul 2>&1

:: =========================
:: 10. VIRTUAL MEMORY OPTIMIZATION
:: =========================
:Pagefile
echo [*] Optimizing virtual memory settings...
echo [%date% %time%] Pagefile started >> "%LOG%"

:: Set system-managed pagefile
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=True >nul 2>&1

:: =========================
:: 11. NETWORK & BANDWIDTH USAGE
:: =========================
:Bandwidth
echo [*] Optimizing network bandwidth usage...
echo [%date% %time%] Bandwidth started >> "%LOG%"

:: Already handled Delivery Optimization above

:: =========================
:: 12. DISABLE REMOTE ASSISTANCE & SUGGESTIONS
:: =========================
:Remote
echo [*] Disabling Remote Assistance and suggestions...
echo [%date% %time%] Remote started >> "%LOG%"

:: Disable Remote Assistance
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f >nul 2>&1

:: Disable suggestions in Start
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f >nul 2>&1

:: =========================
:: 13. DISABLE BACKGROUND APPS & ADVERTISING
:: =========================
:Background
echo [*] Disabling background apps and advertising features...
echo [%date% %time%] Background started >> "%LOG%"

:: Disable background apps (per user)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f >nul 2>&1

:: Disable advertising features
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f >nul 2>&1

:: =========================
:: 14. SYSTEM INTEGRITY CHECK
:: =========================
:Integrity
echo [*] Running system integrity checks...
echo [%date% %time%] Integrity started >> "%LOG%"

sfc /scannow >> "%LOG%" 2>&1
DISM /Online /Cleanup-Image /RestoreHealth >> "%LOG%" 2>&1

:: =========================
:: 15. SUMMARY & REBOOT PROMPT
:: =========================
:Summary
echo.
echo =========================
echo  PC Tweaker Optimization Complete!
echo =========================
echo.
echo [*] All optimizations applied.
echo [*] Backups saved to: %BACKUP_DIR%
echo [*] Log file: %LOG%
echo [*] No critical system features (Store, Defender, Updates) were removed.
echo.
:: =========================
:: FINAL AUTHORSHIP CREDIT (DO NOT REMOVE)
:: =========================
echo  -------------------------------------------------------------
echo  ||             Optimized by: eulfen                        ||
echo  ||        https://github.com/eulfen  |  @eulfen            ||
echo  -------------------------------------------------------------
echo.
echo  Respect the author. Share responsibly.                      
echo.

echo [%date% %time%] Script completed >> "%LOG%"

choice /C YN /N /M "Reboot now to apply all changes? (Y/N): "
if errorlevel 2 goto :eof
shutdown /r /t 5

exit /b 0