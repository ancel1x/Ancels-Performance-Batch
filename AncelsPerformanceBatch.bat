@echo off

:: Version #
Set Version=6.0

:: Enable Delayed Expansion
setlocal enabledelayedexpansion

:: Set Powershell Execution Policy to Unrestricted
powershell "Set-ExecutionPolicy Unrestricted"

:: Batch File Log
echo Ancel's Performance Batch Log >APB_Log.txt

:: Enable ANSI Escape Sequences
reg add "HKCU\CONSOLE" /v "VirtualTerminalLevel" /t REG_DWORD /d "1" /f >> APB_Log.txt

set z=[7m
set i=[1m
set q=[0m
echo %z%Do you want to Create a Restore Point?%q%
echo.
echo %i%Yes = 1%q%
echo.
echo %i%No = 2%q%
echo.
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto RestorePoint
if '%choice%'=='2' goto Continue

:RestorePoint
:: Creating Restore Point
echo Creating Restore Point
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "SystemRestorePointCreationFrequency" /t REG_DWORD /d "0" /f >> APB_Log.txt
powershell -ExecutionPolicy Bypass -Command "Checkpoint-Computer -Description 'Ancels Performance Batch' -RestorePointType 'MODIFY_SETTINGS'" >> APB_Log.txt

:Continue
cls

:: Disable UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f >> APB_Log.txt

:: Getting Admin Permissions https://stackoverflow.com/questions/1894967/how-to-request-administrator-access-inside-a-batch-file
echo Checking for Administrative Privelages...
timeout /t 3 /nobreak > NUL
IF "%PROCESSOR_ARCHITECTURE%" EQU "amd64" (
>nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\SysWOW64\config\system"
) ELSE (
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
)

if '%errorlevel%' NEQ '0' (
    goto UACPrompt
) else ( goto GotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params= %*
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0"" %params:"=""%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:GotAdmin
    pushd "%CD%"
    CD /D "%~dp0"

:: Main Menu
:Menu
chcp 65001 >nul 2>&1
cls
set c=[33m
set t=[0m
set w=[95m
set y=[0m
set u=[4m
set q=[0m
echo.
echo.
echo.
echo.
echo      %w%█████%y%%c%╗%t% %w%███%y%%c%╗%t%   %w%██%y%%c%╗%t% %w%██████%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%██%y%%c%╗%t%     %w%███████%y%%c%╗%t%    %w%████████%y%%c%╗%t%%w%██%y%%c%╗%t%    %w%██%y%%c%╗%t%%w%███████%y%%c%╗%t% %w%█████%y%%c%╗%t% %w%██%y%%c%╗%t%  %w%██%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%██████%y%%c%╗%t% 
echo     %w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%%w%████%y%%c%╗%t%  %w%██%y%%c%║%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%║%t%     %w%██%y%%c%╔════╝    ╚══%t%%w%██%y%%c%╔══╝%t%%w%██%y%%c%║%t%    %w%██%y%%c%║%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%%w%██%y%%c%║%t% %w%██%y%%c%╔╝%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%
echo     %w%███████%y%%c%║%t%%w%██%y%%c%╔%t%%w%██%y%%c%╗%t% %w%██%y%%c%║%t%%w%██%y%%c%║%t%     %w%█████%y%%c%╗%t%  %w%██%y%%c%║%t%     %w%███████%y%%c%╗%t%       %w%██%y%%c%║%t%   %w%██%y%%c%║%t% %w%█%y%%c%╗%t% %w%██%y%%c%║%t%%w%█████%y%%c%╗%t%  %w%███████%y%%c%║%t%%w%█████%y%%c%╔╝%t% %w%█████%y%%c%╗%t%  %w%██████%y%%c%╔╝%t%
echo     %w%██%y%%c%╔══%t%%w%██%y%%c%║%t%%w%██%y%%c%║╚%t%%w%██%y%%c%╗%t%%w%██%y%%c%║%t%%w%██%y%%c%║%t%     %w%██%y%%c%╔══╝%t%  %w%██%y%%c%║     ╚════%t%%w%██%y%%c%║%t%       %w%██%y%%c%║%t%   %w%██%y%%c%║%t%%w%███%y%%c%╗%t%%w%██%y%%c%║%t%%w%██%y%%c%╔══╝%t%  %w%██%y%%c%╔══%t%%w%██%y%%c%║%t%%w%██%y%%c%╔═%t%%w%██%y%%c%╗%t% %w%██%y%%c%╔══╝%t%  %w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%
echo     %w%██%y%%c%║%t%  %w%██%y%%c%║%t%%w%██%y%%c%║ ╚%t%%w%████%y%%c%║╚%t%%w%██████%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%███████%y%%c%║%t%       %w%██%y%%c%║   ╚%t%%w%███%y%%c%╔%t%%w%███%y%%c%╔╝%t%%w%███████%y%%c%╗%t%%w%██%y%%c%║%t%  %w%██%y%%c%║%t%%w%██%y%%c%║%t%  %w%██%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%██%y%%c%║%t%  %w%██%y%%c%║%t%
echo     %c%╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚══════╝╚══════╝       ╚═╝    ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝%t%                                                                                                                                                        
echo                                                   %c%Created By: ancel_%t%     
echo                                                      %c%%u%Version: %Version%%q%%t%
echo.
echo %w%════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════%y%
echo.
echo.
echo.
echo                           %w%[%y% %c%%u%1%q%%t% %w%]%y% %c%Performance Optimizations%t%                 %w%[%y% %c%%u%2%q% %t%%w%]%y% %c%KBM Optimizations%t%
echo. 
echo.
echo                           %w%[%y% %c%%u%3%q%%t% %w%]%y% %c%Disable Telemetry%t%                         %w%[%y% %c%%u%4%q% %t%%w%]%y% %c%Network%t%
echo.
echo.
echo                           %w%[%y% %c%%u%5%q%%t% %w%]%y% %c%Debloat Windows%t%                           %w%[%y% %c%%u%6%q%%t% %w%]%y% %c%Other%t%
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto PerformanceOptimizations
if '%choice%'=='2' goto KBMOptimizations
if '%choice%'=='3' goto DisableTelemetry
if '%choice%'=='4' goto Network
if '%choice%'=='5' goto DebloatWindows
if '%choice%'=='6' goto Other

:PerformanceOptimizations
cls

set z=[7m
set i=[1m
set q=[0m
echo %z%Are you on Windows 10 or 11?%q%
echo.
echo %i%Windows 10 = 1%q%
echo.
echo %i%Windows 11 = 2%q%
echo.
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto Windows10
if '%choice%'=='2' goto Windows11

:Windows10
cls

:: BCD Tweaks
echo Applying BCD Tweaks
bcdedit /set useplatformclock No >> APB_Log.txt
bcdedit /set platformtick No >> APB_Log.txt
bcdedit /set disabledynamictick Yes >> APB_Log.txt
bcdedit /set tscsyncpolicy Enhanced >> APB_Log.txt
bcdedit /set firstmegabytepolicy UseAll >> APB_Log.txt
bcdedit /set avoidlowmemory 0x8000000 >> APB_Log.txt
bcdedit /set nolowmem Yes >> APB_Log.txt
bcdedit /set allowedinmemorysettings 0x0 >> APB_Log.txt
bcdedit /set isolatedcontext No >> APB_Log.txt
bcdedit /set vsmlaunchtype Off >> APB_Log.txt
bcdedit /set vm No >> APB_Log.txt
bcdedit /set x2apicpolicy Enable >> APB_Log.txt
bcdedit /set configaccesspolicy Default >> APB_Log.txt
bcdedit /set MSI Default >> APB_Log.txt
bcdedit /set usephysicaldestination No >> APB_Log.txt
bcdedit /set usefirmwarepcisettings No >> APB_Log.txt
bcdedit /set disableelamdrivers Yes >> APB_Log.txt
bcdedit /set pae ForceEnable >> APB_Log.txt
bcdedit /set nx optout >> APB_Log.txt
bcdedit /set highestmode Yes >> APB_Log.txt
bcdedit /set forcefipscrypto No >> APB_Log.txt
bcdedit /set noumex Yes >> APB_Log.txt
bcdedit /set uselegacyapicmode No >> APB_Log.txt
bcdedit /set ems No >> APB_Log.txt
bcdedit /set extendedinput Yes >> APB_Log.txt
bcdedit /set debug No >> APB_Log.txt
bcdedit /set hypervisorlaunchtype Off >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Delete Microcode
echo Deleting Microcode
takeown /f "C:\Windows\System32\mcupdate_GenuineIntel.dll" /r /d y >> APB_Log.txt
takeown /f "C:\Windows\System32\mcupdate_AuthenticAMD.dll" /r /d y >> APB_Log.txt
del "C:\Windows\System32\mcupdate_GenuineIntel.dll" /s /f /q >> APB_Log.txt
del "C:\Windows\System32\mcupdate_AuthenticAMD.dll" /s /f /q >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:Windows11
cls

:: BCD Tweaks
echo Applying BCD Tweaks
bcdedit /set useplatformclock No >> APB_Log.txt
bcdedit /seplatformtick No >> APB_Log.txt
bcdedit /set disabledynamictick Yes >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Mitigations
echo Disabling Mitigations
powershell "ForEach($v in (Get-Command -Name \"Set-ProcessMitigation\").Parameters[\"Disable\"].Attributes.ValidValues){Set-ProcessMitigation -System -Disable $v.ToString() -ErrorAction SilentlyContinue}" >> APB_Log.txt

powershell "Remove-Item -Path \"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\" -Recurse -ErrorAction SilentlyContinue" >> APB_Log.txt

reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f >> APB_Log.txt

:: Sub Mitigations
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "222222222222222222222222222222222222222222222222" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: NTFS Tweaks
echo Applying NTFS Tweaks
fsutil behavior set memoryusage 2 >> APB_Log.txt
fsutil behavior set mftzone 4 >> APB_Log.txt
fsutil behavior set disablelastaccess 1 >> APB_Log.txt
fsutil behavior set disabledeletenotify 0 >> APB_Log.txt
fsutil behavior set encryptpagingfile 0 >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Memory Compression
echo Disabling Memory Compression
PowerShell -Command "Disable-MMAgent -MemoryCompression" >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Page Combining
echo Disabling Page Combining
PowerShell -Command "Disable-MMAgent -PageCombining" >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Win32Priority
echo Setting Win32Priority
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Large System Cache
echo Enabling Large System Cache
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Fast Startup
echo Disabling Fast Startup
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Hibernation
echo Disabling Hibernation
powercfg /h off
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "SleepReliabilityDetailedDiagnostics" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Sleep Study
echo Disabling Sleep Study
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "SleepStudyDisabled" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable DEP
echo Disabling DEP
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v "DEPOff" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Automatic Maintenance
echo Disabling Automatic Maintenance
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Paging Executive
echo Disabling Paging Executive
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Force contiguous memory allocation in the DirectX Graphics Kernel (melodytheneko)
echo Forcing contiguous memory allocation in the DirectX Graphics Kernel
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DpiMapIommuContiguous" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable FTH
echo Disabling Fault Tolerant Heap
reg add "HKLM\SOFTWARE\Microsoft\FTH" /v "Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable ASLR
echo Disabling Address Space Layout Randomization
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "MoveImages" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Power Throttling
echo Disabling Power Throttling
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\ModernSleep" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PlatformAoAcOverride" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EventProcessorEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CsEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Enable HAGS
echo Enabling Hardware-Accelerated Gpu Scheduling
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d "2" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Enable Distribute Timers
echo Enabling Distribution of Timers
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DistributeTimers" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Enable GameMode
echo Enabling GameMode
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Gamebar
echo Disabling Gamebar
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" /v "ActivationType" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: MenuShowDelay
echo Reducing Menu Delay
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable GpuEnergyDrv
echo Disabling GPU Energy Driver
reg add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDr" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Energy Logging
echo Disabling Energy Logging
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "DisableTaggedEnergyLogging" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxApplication" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxTagPerApplication" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Windows Insider Experiments
echo Disabling Windows Insider Experiments
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /v "value" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: MMCSS
echo Setting MMCSS
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NoLazyMode" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "AlwaysOn" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Timestamp
echo Setting Time Stamp Interval
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "TimeStampInterval" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "IoPriority" /t REG_DWORD /d "3" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: CSRSS
echo Setting CSRSS to Realtime
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: System Responsiveness
echo Setting System Responsiveness
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "10" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Windows Remediation
echo Disabling Windows Remediation
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RemediationRequired" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Windows Tips
echo Disabling Windows Tips
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Windows Spotlight
echo Disabling Windows Spotlight
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Shared Experiences
echo Disabling Shared Experiences
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" /v "CdpSessionUserAuthzPolicy" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" /v "NearShareChannelUserAuthzPolicy" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Stop Explorer from Showing Frequent/Recent Files
echo Disabling Frequent/Recent Files
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "TelemetrySalt" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Tailored Experiences
echo Disabling Tailored Experiences
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Search History Logging
echo Disabling Search History Logging
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "HistoryViewEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Device History
echo Disabling Bing Search
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "DeviceHistoryEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Bing Search
echo Disabling Bing Search
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Notifications
echo Disabling Notifications
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\QuietHours" /v "Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" /v "Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.AutoPlay" /v "Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.LowDisk" /v "Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.Print.Notification" /v "Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.WiFiNetworkManager" /v "Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Windows Privacy Settings
echo Setting Windows Privacy Settings
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /t REG_SZ /d "Deny" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Deny" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Deny" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /v "Value" /t REG_SZ /d "Deny" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData\Microsoft.Win32WebViewHost_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Allow" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Deny" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput" /v "Value" /t REG_SZ /d "Deny" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\Microsoft.Win32WebViewHost_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Prompt" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v "Value" /t REG_SZ /d "Allow" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.Win32WebViewHost_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Prompt" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Deny" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation\Microsoft.AccountsControl_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Prompt" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Deny" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Deny" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Allow" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\Microsoft.Win32WebViewHost_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Allow" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Stop Windows from Reinstalling Preinstalled apps
echo Stopping Windows from Reinstalling Preinstalled apps
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Suggestions at Start
echo Disabling Windows Suggestions
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314559Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-280815Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314563Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-202914Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Startup Apps
echo Disabling Startup Apps
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Discord" /t REG_BINARY /d "0300000066AF9C7C5A46D901" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Synapse3" /t REG_BINARY /d "030000007DC437B0EA9FD901" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Spotify" /t REG_BINARY /d "0300000070E93D7B5A46D901" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "EpicGamesLauncher" /t REG_BINARY /d "03000000F51C70A77A48D901" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "RiotClient" /t REG_BINARY /d "03000000A0EA598A88B2D901" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Steam" /t REG_BINARY /d "03000000E7766B83316FD901" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Microsoft Setting Synchronization
echo Disabling Setting Synchronization
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v "Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /v "Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" /v "Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /v "Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Windows Error Reporting
echo Disabling Windows Error Reporting
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DoReport" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Setting Service Priorities & Boost
echo Setting Service Priorities
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "PassiveIntRealTimeWorkerPriority" /t REG_DWORD /d "18" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\KernelVelocity" /v "DisableFGBoostDecay" /t REG_DWORD /d "1" /f >> APB_Log.txt

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\audiodg.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "2" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\audiodg.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "2" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Windows Defender
echo Disabling Windows Defender
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableGenericReports" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "LocalSettingOverrideSpynetReporting" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Threats" /v "Threats_ThreatSeverityDefaultAction" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "1" /t REG_SZ /d "6" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "2" /t REG_SZ /d "6" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "4" /t REG_SZ /d "6" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "5" /t REG_SZ /d "6" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration" /v "Notification_Suppress" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotification" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotificationOnLockScreen" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MsMpEng.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MsMpEngCP.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Enable FSO
echo Enabling Full Screen Optimizations
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_DSEBehavior" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Latency Tolerance (melodytheneko)
echo Setting Latency Tolerance
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "RtlCapabilityCheckLatency" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyActivelyUsed" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleLongTime" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleMonitorOff" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleNoContext" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleShortTime" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleVeryLongTime" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0MonitorOff" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1MonitorOff" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceMemory" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContext" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContextMonitorOff" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceOther" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceTimerPeriod" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceActivelyUsed" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceMonitorOff" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceNoContext" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "Latency" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MaxIAverageGraphicsLatencyInOneBucket" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MiracastPerfTrackGraphicsLatency" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "TransitionLatency" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Resource Policy Values
echo Setting Resource Policy Store Values
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\HardCap0" /v "CapPercentage" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\HardCap0" /v "SchedulingType" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\Paused" /v "CapPercentage" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\Paused" /v "SchedulingType" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapFull" /v "CapPercentage" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapFull" /v "SchedulingType" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapLow" /v "CapPercentage" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapLow" /v "SchedulingType" /t REG_DWORD /d "0" /f >> APB_Log.txt

reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\BackgroundDefault" /v "IsLowPriority" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Frozen" /v "IsLowPriority" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenDNCS" /v "IsLowPriority" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenDNK" /v "IsLowPriority" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenPPLE" /v "IsLowPriority" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Paused" /v "IsLowPriority" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\PausedDNK" /v "IsLowPriority" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Pausing" /v "IsLowPriority" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\PrelaunchForeground" /v "IsLowPriority" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\ThrottleGPUInterference" /v "IsLowPriority" /t REG_DWORD /d "0" /f >> APB_Log.txt

reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Critical" /v "BasePriority" /t REG_DWORD /d "82" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Critical" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\CriticalNoUi" /v "BasePriority" /t REG_DWORD /d "82" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\CriticalNoUi" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\EmptyHostPPLE" /v "BasePriority" /t REG_DWORD /d "82" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\EmptyHostPPLE" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\High" /v "BasePriority" /t REG_DWORD /d "82" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\High" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Low" /v "BasePriority" /t REG_DWORD /d "82" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Low" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Lowest" /v "BasePriority" /t REG_DWORD /d "82" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Lowest" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Medium" /v "BasePriority" /t REG_DWORD /d "82" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Medium" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\MediumHigh" /v "BasePriority" /t REG_DWORD /d "82" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\MediumHigh" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\StartHost" /v "BasePriority" /t REG_DWORD /d "82" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\StartHost" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryHigh" /v "BasePriority" /t REG_DWORD /d "82" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryHigh" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryLow" /v "BasePriority" /t REG_DWORD /d "82" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryLow" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >> APB_Log.txt

reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\IO\NoCap" /v "IOBandwidth" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap" /v "CommitLimit" /t REG_DWORD /d "4294967295" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap" /v "CommitTarget" /t REG_DWORD /d "4294967295" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable P-States
echo Disabling P-States
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /L "PCI\VEN_"') do (
	for /f "tokens=3" %%a in ('reg query "HKLM\SYSTEM\ControlSet001\Enum\%%i" /v "Driver"') do (
		for /f %%i in ('echo %%a ^| findstr "{"') do (
		     reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\%%i" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f >> APB_Log.txt
                   )
                )
             )        
timeout /t 3 /nobreak > NUL

cls
set z=[7m
set i=[1m
set q=[0m
echo %z%What GPU Do you Have?%q%
echo.
echo %i%NVIDIA = 1%q%
echo.
echo %i%AMD = 2%q%
echo.
echo %i%IGPU = 3%q%
echo.
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto NVIDIA
if '%choice%'=='2' goto AMD
if '%choice%'=='3' goto IGPU

:NVIDIA

:: NVIDIA Inspector Profile
echo Applying NVIDIA Inspector Profile
curl -g -k -L -# -o "%temp%\nvidiaProfileInspector.zip" "https://github.com/Orbmu2k/nvidiaProfileInspector/releases/latest/download/nvidiaProfileInspector.zip" >> APB_Log.txt
powershell -NoProfile Expand-Archive '%temp%\nvidiaProfileInspector.zip' -DestinationPath 'C:\NvidiaProfileInspector\' >> APB_Log.txt
curl -g -k -L -# -o "C:\NvidiaProfileInspector\ancel_nv_profile.nip" "https://github.com/ancel1x/Ancels-Performance-Batch/raw/main/bin/ancel_nv_profile.nip" >> APB_Log.txt
start "" /wait "C:\NvidiaProfileInspector\nvidiaProfileInspector.exe" "C:\NvidiaProfileInspector\ancel_nv_profile.nip" >> APB_Log.txt
timeout /t 3 /nobreak > NUL

:: Enable MSI Mode for GPU
echo Enabling MSI Mode
for /f %%g in ('wmic path win32_videocontroller get PNPDeviceID ^| findstr /L "VEN_"') do (
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /t REG_DWORD /d "0" /f >> APB_Log.txt
)
timeout /t 1 /nobreak > NUL

:: NVIDIA Latency Tolerance
echo Setting NVIDIA Latency Tolerance
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "D3PCLatency" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "F1TransitionLatency" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "LOWLATENCY" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Node3DLowLatency" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PciLatencyTimerControl" /t REG_DWORD /d "20" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMDeepL1EntryLatencyUsec" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMaxFtuS" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMinFtuS" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcPerioduS" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrEiIdleThresholdUs" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrIdleThresholdUs" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrRgIdleThresholdUs" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrMsIdleThresholdUs" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipDPCDelayUs" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipTimingMarginUs" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectJITFlipMsHybridFlipDelayUs" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrCursorMarginUs" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMarginUs" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMaxUs" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Force Contigous Memory Allocation
echo Forcing Contigous Memory Allocation
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PreferSystemMemoryContiguous" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable HDCP
echo Disabling High-bandwidth Digital Content Protection
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMHdcpKeyGlobZero" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable TCC
echo Disabling TCC
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "TCCSupported" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Tiled Display
echo Disabling Tiled Display
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableTiledDisplay" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable NVIDIA Telemetry
echo Disabling NVIDIA Telemetry
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "NvBackend" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /t REG_DWORD /d "0" /f >> APB_Log.txt
schtasks /change /disable /tn "NvTmRep_CrashReport1_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >> APB_Log.txt
schtasks /change /disable /tn "NvTmRep_CrashReport2_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >> APB_Log.txt
schtasks /change /disable /tn "NvTmRep_CrashReport3_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >> APB_Log.txt
schtasks /change /disable /tn "NvTmRep_CrashReport4_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >> APB_Log.txt
schtasks /change /disable /tn "NvDriverUpdateCheckDaily_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >> APB_Log.txt
schtasks /change /disable /tn "NVIDIA GeForce Experience SelfUpdate_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >> APB_Log.txt
schtasks /change /disable /tn "NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable NVIDIA Display Power Saving
echo Disabling NVIDIA Display Power Saving
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "DisplayPowerSaving" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Write Combining
echo Disabling Write Combining
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableWriteCombining" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Enable DPC'S for each Core
echo Enabling DPC'S for each Core
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\NVAPI" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Video Redraw Acceleration
echo Setting Driver Acceleration
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Acceleration.Level" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable NVIDIA 3D Vision Shortcuts
echo Disabling NVIDIA Shortcuts
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DesktopStereoShortcuts" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "FeatureControl" /t REG_DWORD /d "4" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Filter
echo Disabling Filter
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "NVDeviceSupportKFilter" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Increased Dedicated Video Memory
echo Increasing Dedicated Video Memory
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmCacheLoc" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Set NVIDIA Driver Package Install Directory
echo Setting Driver Package Install Directory
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmDisableInst2Sys" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: ReAllocate DMA Buffers
echo ReAllocating DMA Buffers
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmFbsrPagedDMA" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Change PCounter Permissions
echo Changing Performance Counter Permissions
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmProfilingAdminOnly" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable DX Event Tracking
echo Disabling DirectX Event Tracking
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "TrackResetEngine" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Verifications in Block Transfer Operations
echo Disabling Verifications Block Transfer Operations
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "ValidateBlitSubRects" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable NVIDIA WDDM TDR
echo Disabling NVIDIA TDR
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLevel" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDelay" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDdiDelay" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDebugMode" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLimitCount" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLimitTime" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrTestMode" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

echo Finished Performance Optimizations
timeout /t 5 /nobreak > NUL
goto CompletedPerfOptimizations

:AMD

:: Enable MSI Mode for GPU
echo Enabling MSI Mode
for /f %%g in ('wmic path win32_videocontroller get PNPDeviceID ^| findstr /L "VEN_"') do (
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /t REG_DWORD /d "0" /f >> APB_Log.txt
)
timeout /t 1 /nobreak > NUL

:: Disable Override Referesh Rate
echo Disabling Display Refresh Rate Override
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "3D_Refresh_Rate_Override_DEF" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable SnapShot
echo Disabling SnapShot
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AllowSnapshot" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Anti Aliasing
echo Disabling Anti Aliasing
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AAF_NA" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AntiAlias_NA" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "ASTT_NA" /t REG_SZ /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable AllowSubscription
echo Disabling Subscriptions
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AllowSubscription" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Anisotropic Filtering
echo Disabling Anisotropic Filtering
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AreaAniso_NA" /t REG_SZ /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable AllowRSOverlay
echo Disabling Radeon Overlay
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AllowRSOverlay" /t REG_SZ /d "false" /f >> APB_Log.txt 
timeout /t 1 /nobreak > NUL

:: Enable Adaptive DeInterlacing
echo Enabling Adaptive DeInterlacing
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Adaptive De-interlacing" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable AllowSkins
echo Disabling Skins
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AllowSkins" /t REG_SZ /d "false" /f >> APB_Log.txt 
timeout /t 1 /nobreak > NUL

:: Disable AutoColorDepthReduction_NA
echo Disabling Automatic Color Depth Reduction
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AutoColorDepthReduction_NA" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Power Gating
echo Disabling Power Gating
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableSAMUPowerGating" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableUVDPowerGatingDynamic" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableVCEPowerGating" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisablePowerGating" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDrmdmaPowerGating" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Clock Gating
echo Disabling Clock Gating
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableVceSwClockGating" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUvdClockGating" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable ASPM
echo Disabling Active State Power Management
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableAspmL0s" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableAspmL1" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable ULPS
echo Disabling Ultra Low Power States
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps_NA" /t REG_SZ /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Enable De-Lag
echo Enabling De-Lag
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_DeLagEnabled" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable FRT
echo Disabling Frame Rate Target
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_FRTEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable DMA
echo Disabling DMA
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDMACopy" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Enable BlockWrite
echo Enable BlockWrite
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableBlockWrite" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable StutterMode
echo Disabling Stutter Mode
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "StutterMode" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable GPU Mem Clock Sleep State
echo Disabling GPU Memory Clock Sleep State
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_SclkDeepSleepDisable" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Thermal Throttling
echo Disabling Thermal Throttling
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_ThermalAutoThrottlingEnable" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Setting Main3D
echo Setting Main3D
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Main3D_DEF" /t REG_SZ /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Main3D" /t REG_BINARY /d "3100" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Setting FlipQueueSize
echo Setting FlipQueueSize
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "FlipQueueSize" /t REG_BINARY /d "3100" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Setting Shader Cache
echo Setting Shader Cache Size
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ShaderCache" /t REG_BINARY /d "3200" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Configuring TFQ
echo Configuring TFQ
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TFQ" /t REG_BINARY /d "3200" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable HDCP
echo Disabling High-Bandwidth Digital Content Protection
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\\DAL2_DATA__2_0\DisplayPath_4\EDID_D109_78E9\Option" /v "ProtectionControl" /t REG_BINARY /d "0100000001000000" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable GPU Power Down
echo Disabling GPU Power Down
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_GPUPowerDownEnabled" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable AMD Logging
echo Disabling AMD Logging
reg add "HKLM\SYSTEM\CurrentControlSet\Services\amdlog" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: AMD Tweaks (melodytheneko)
echo Applying Melody AMD Tweaks
for %%a in (LTRSnoopL1Latency LTRSnoopL0Latency LTRNoSnoopL1Latency LTRMaxNoSnoopLatency KMD_RpmComputeLatency
        DalUrgentLatencyNs memClockSwitchLatency PP_RTPMComputeF1Latency PP_DGBMMMaxTransitionLatencyUvd
        PP_DGBPMMaxTransitionLatencyGfx DalNBLatencyForUnderFlow
        BGM_LTRSnoopL1Latency BGM_LTRSnoopL0Latency BGM_LTRNoSnoopL1Latency BGM_LTRNoSnoopL0Latency
        BGM_LTRMaxSnoopLatencyValue BGM_LTRMaxNoSnoopLatencyValue) do (reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "%%a" /t REG_DWORD /d "1" /f >> APB_Log.txt
)

echo Finished Performance Optimizations
timeout /t 5 /nobreak > NUL
goto CompletedPerfOptimizations

:IGPU
:: Dedicated Segment Size
echo Setting Dedicated Segment Size
reg add "HKLM\SOFTWARE\Intel\GMM" /v "DedicatedSegmentSize" /t REG_DWORD /d "512" /f >> APB_Log.txt
timeout /t 5 /nobreak > NUL

goto CompletedPerfOptimizations


:CompletedPerfOptimizations
cls
echo Completed Performance Optimizations
timeout /t 3 /nobreak > NUL
cls
set c=[33m
set t=[0m
set w=[95m
set y=[0m
set u=[4m
set q=[0m
echo.
echo.
echo.
echo.
echo      %w%█████%y%%c%╗%t% %w%███%y%%c%╗%t%   %w%██%y%%c%╗%t% %w%██████%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%██%y%%c%╗%t%     %w%███████%y%%c%╗%t%    %w%████████%y%%c%╗%t%%w%██%y%%c%╗%t%    %w%██%y%%c%╗%t%%w%███████%y%%c%╗%t% %w%█████%y%%c%╗%t% %w%██%y%%c%╗%t%  %w%██%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%██████%y%%c%╗%t% 
echo     %w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%%w%████%y%%c%╗%t%  %w%██%y%%c%║%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%║%t%     %w%██%y%%c%╔════╝    ╚══%t%%w%██%y%%c%╔══╝%t%%w%██%y%%c%║%t%    %w%██%y%%c%║%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%%w%██%y%%c%║%t% %w%██%y%%c%╔╝%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%
echo     %w%███████%y%%c%║%t%%w%██%y%%c%╔%t%%w%██%y%%c%╗%t% %w%██%y%%c%║%t%%w%██%y%%c%║%t%     %w%█████%y%%c%╗%t%  %w%██%y%%c%║%t%     %w%███████%y%%c%╗%t%       %w%██%y%%c%║%t%   %w%██%y%%c%║%t% %w%█%y%%c%╗%t% %w%██%y%%c%║%t%%w%█████%y%%c%╗%t%  %w%███████%y%%c%║%t%%w%█████%y%%c%╔╝%t% %w%█████%y%%c%╗%t%  %w%██████%y%%c%╔╝%t%
echo     %w%██%y%%c%╔══%t%%w%██%y%%c%║%t%%w%██%y%%c%║╚%t%%w%██%y%%c%╗%t%%w%██%y%%c%║%t%%w%██%y%%c%║%t%     %w%██%y%%c%╔══╝%t%  %w%██%y%%c%║     ╚════%t%%w%██%y%%c%║%t%       %w%██%y%%c%║%t%   %w%██%y%%c%║%t%%w%███%y%%c%╗%t%%w%██%y%%c%║%t%%w%██%y%%c%╔══╝%t%  %w%██%y%%c%╔══%t%%w%██%y%%c%║%t%%w%██%y%%c%╔═%t%%w%██%y%%c%╗%t% %w%██%y%%c%╔══╝%t%  %w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%
echo     %w%██%y%%c%║%t%  %w%██%y%%c%║%t%%w%██%y%%c%║ ╚%t%%w%████%y%%c%║╚%t%%w%██████%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%███████%y%%c%║%t%       %w%██%y%%c%║   ╚%t%%w%███%y%%c%╔%t%%w%███%y%%c%╔╝%t%%w%███████%y%%c%╗%t%%w%██%y%%c%║%t%  %w%██%y%%c%║%t%%w%██%y%%c%║%t%  %w%██%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%██%y%%c%║%t%  %w%██%y%%c%║%t%
echo     %c%╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚══════╝╚══════╝       ╚═╝    ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝%t%                                                                                                                                                        
echo                                                   %c%Created By: ancel_%t%     
echo                                                      %c%%u%Version: %Version%%q%%t%
echo.
echo %w%════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════%y%
echo.
echo.
echo.
echo.
echo.
echo                                              %w%[%y% %c%%u%1%q%%t% %w%]%y% %c%Menu%t%               %w%[%y% %c%%u%2%q%%t% %w%]%y% %c%Exit%t%
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto Menu
if '%choice%'=='2' goto Close


:KBMOptimizations
cls

:: Disable Sticky Keys
echo Disabling Sticky Keys
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Filter Keys
echo Disabling Filter Keys
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "122" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Toggle Keys
echo Disabling Toggle Keys
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "58" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: MSI Mode for USB Controller
echo Enabling MSI Mode for USB Controller
for /f %%i in ('wmic path Win32_USBController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable USB PowerSavings
echo Disabling USB PowerSavings
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "D3ColdSupported" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnableSelectiveSuspend" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f >> APB_Log.txt
)
timeout /t 1 /nobreak > NUL

:: Disable Selective Suspend
echo Disabling USB Selective Suspend
reg add "HKLM\SYSTEM\CurrentControlSet\Services\USB" /v "DisableSelectiveSuspend" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Mouse Acceleration
echo Disabling Mouse Acceleration
reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Enable 1:1 Pixel Mouse Movements
echo Enabling 1:1 Pixel Mouse Movements
reg add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Reduce Keyboard Repeat Delay
echo Reducing Keyboard Repeat Delay
reg add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_SZ /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Reduce Keyboard Repeat Rate
echo Increasing Keyboard Repeat Rate
reg add "HKCU\Control Panel\Keyboard" /v "KeyboardSpeed" /t REG_SZ /d "31" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Mouse Data Queue Size
echo Setting Mouse Data Queue Size
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "16" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Keyboard Data Queue Size
echo Setting Keyboard Data Queue Size
reg add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "16" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: DebugPollInterval (BeersE#9366)
echo Setting Debug Poll Interval
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DebugPollInterval" /t REG_DWORD /d "1000" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Setting CSRSS to Realtime
echo Setting CSRSS to Realtime
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Mouse Smoothing
cls
set z=[7m
set i=[1m
set q=[0m
echo %z%Do you use the touchpad on a laptop?%q%
echo.
echo %i%Yes = 1%q%
echo.
echo %i%No = 2%q%
echo.
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto CompletedKBMOptimizations
if '%choice%'=='2' goto DisableMouseSmoothing

:DisableMouseSmoothing
cls
:: Disable Mouse Smoothing
echo Disabling Mouse Smoothing
reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "00000000000000000000000000000000000000000000000000000000000000000000000000000000" /f >> APB_Log.txt
reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "00000000000000000000000000000000000000000000000000000000000000000000000000000000" /f >> APB_Log.txt
timeout /t 2 /nobreak > NUL

goto CompletedKBMOptimizations

:CompletedKBMOptimizations
cls
echo Completed KBM Optimizations
timeout /t 3 /nobreak > NUL
cls
set c=[33m
set t=[0m
set w=[95m
set y=[0m
set u=[4m
set q=[0m
echo.
echo.
echo.
echo.
echo      %w%█████%y%%c%╗%t% %w%███%y%%c%╗%t%   %w%██%y%%c%╗%t% %w%██████%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%██%y%%c%╗%t%     %w%███████%y%%c%╗%t%    %w%████████%y%%c%╗%t%%w%██%y%%c%╗%t%    %w%██%y%%c%╗%t%%w%███████%y%%c%╗%t% %w%█████%y%%c%╗%t% %w%██%y%%c%╗%t%  %w%██%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%██████%y%%c%╗%t% 
echo     %w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%%w%████%y%%c%╗%t%  %w%██%y%%c%║%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%║%t%     %w%██%y%%c%╔════╝    ╚══%t%%w%██%y%%c%╔══╝%t%%w%██%y%%c%║%t%    %w%██%y%%c%║%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%%w%██%y%%c%║%t% %w%██%y%%c%╔╝%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%
echo     %w%███████%y%%c%║%t%%w%██%y%%c%╔%t%%w%██%y%%c%╗%t% %w%██%y%%c%║%t%%w%██%y%%c%║%t%     %w%█████%y%%c%╗%t%  %w%██%y%%c%║%t%     %w%███████%y%%c%╗%t%       %w%██%y%%c%║%t%   %w%██%y%%c%║%t% %w%█%y%%c%╗%t% %w%██%y%%c%║%t%%w%█████%y%%c%╗%t%  %w%███████%y%%c%║%t%%w%█████%y%%c%╔╝%t% %w%█████%y%%c%╗%t%  %w%██████%y%%c%╔╝%t%
echo     %w%██%y%%c%╔══%t%%w%██%y%%c%║%t%%w%██%y%%c%║╚%t%%w%██%y%%c%╗%t%%w%██%y%%c%║%t%%w%██%y%%c%║%t%     %w%██%y%%c%╔══╝%t%  %w%██%y%%c%║     ╚════%t%%w%██%y%%c%║%t%       %w%██%y%%c%║%t%   %w%██%y%%c%║%t%%w%███%y%%c%╗%t%%w%██%y%%c%║%t%%w%██%y%%c%╔══╝%t%  %w%██%y%%c%╔══%t%%w%██%y%%c%║%t%%w%██%y%%c%╔═%t%%w%██%y%%c%╗%t% %w%██%y%%c%╔══╝%t%  %w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%
echo     %w%██%y%%c%║%t%  %w%██%y%%c%║%t%%w%██%y%%c%║ ╚%t%%w%████%y%%c%║╚%t%%w%██████%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%███████%y%%c%║%t%       %w%██%y%%c%║   ╚%t%%w%███%y%%c%╔%t%%w%███%y%%c%╔╝%t%%w%███████%y%%c%╗%t%%w%██%y%%c%║%t%  %w%██%y%%c%║%t%%w%██%y%%c%║%t%  %w%██%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%██%y%%c%║%t%  %w%██%y%%c%║%t%
echo     %c%╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚══════╝╚══════╝       ╚═╝    ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝%t%                                                                                                                                                        
echo                                                   %c%Created By: ancel_%t%     
echo                                                      %c%%u%Version: %Version%%q%%t%
echo.
echo %w%════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════%y%
echo.
echo.
echo.
echo.
echo.
echo                                              %w%[%y% %c%%u%1%q%%t% %w%]%y% %c%Menu%t%               %w%[%y% %c%%u%2%q%%t% %w%]%y% %c%Exit%t%
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto Menu
if '%choice%'=='2' goto Close


:DisableTelemetry
cls

:: Disable Telemetry Through Task Scheduler
echo Disabling Telemetry Through Task Scheduler
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\Application Experience\StartupAppTask" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Windows\Application Experience\StartupAppTask" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyUpload" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyUpload" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\Autochk\Proxy" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Windows\Autochk\Proxy" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\Maintenance\WinSAT" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Windows\Maintenance\WinSAT" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\Application Experience\AitAgent" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Windows\Application Experience\AitAgent" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\DiskFootprint\Diagnostics" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Windows\DiskFootprint\Diagnostics" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\FileHistory\File History (maintenance mode)" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\PI\Sqm-Tasks" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Windows\PI\Sqm-Tasks" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\AppID\SmartScreenSpecific" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Windows\AppID\SmartScreenSpecific" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Office\OfficeTelemetryAgentFallBack2016" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Office\OfficeTelemetryAgentFallBack2016" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Office\OfficeTelemetryAgentLogOn2016" >> APB_Log.txt
schtasks /change /tn "\Microsoft\Office\OfficeTelemetryAgentLogOn2016" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Office\OfficeTelemetryAgentLogOn" >> APB_Log.txt
schtasks /change /TN "\Microsoft\Office\OfficeTelemetryAgentLogOn" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoftd\Office\OfficeTelemetryAgentFallBack" >> APB_Log.txt
schtasks /change /TN "\Microsoftd\Office\OfficeTelemetryAgentFallBack" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Office\Office 15 Subscription Heartbeat" >> APB_Log.txt
schtasks /change /TN "\Microsoft\Office\Office 15 Subscription Heartbeat" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" >> APB_Log.txt
schtasks /change /TN "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\Time Synchronization\SynchronizeTime" >> APB_Log.txt
schtasks /change /TN "\Microsoft\Windows\Time Synchronization\SynchronizeTime" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\WindowsUpdate\Automatic App Update" >> APB_Log.txt
schtasks /change /TN "\Microsoft\Windows\WindowsUpdate\Automatic App Update" /disable >> APB_Log.txt
schtasks /end /tn "\Microsoft\Windows\Device Information\Device" >> APB_Log.txt
schtasks /change /TN "\Microsoft\Windows\Device Information\Device" /disable >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Telemetry Through Registry
echo Disabling Telemetry Through Registry
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogEnable" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogLevel" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowCommercialDataPipeline" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "MicrosoftEdgeDataOptIn" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoExplicitFeedback" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoActiveHelp" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "DoSvc" /t REG_DWORD /d "3" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableSensors" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\DeviceHealthAttestationService" /v "DisableSendGenericDriverNotFoundToWER" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" /v "DisableSendGenericDriverNotFoundToWER" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\DriverDatabase\Policies\Settings" /v "DisableSendGenericDriverNotFoundToWER" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Reliability" /v "CEIPEnable" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Reliability" /v "SqmLoggerRunning" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "DisableOptinExperience" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "SqmLoggerRunning" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\IE" /v "SqmLoggerRunning" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\FileHistory" /v "Disabled" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Peernet" /v "Disabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v value /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\DriverDatabase\Policies\Settings" /v "DisableSendGenericDriverNotFoundToWER" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable AutoLoggers
echo Disabling Auto Loggers
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AppModel" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Cellcore" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Circular Kernel Context Logger" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\CloudExperienceHostOobe" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DataMarket" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DiagLog" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\HolographicDevice" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\iclsClient" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\iclsProxy" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Mellanox-Kernel" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-AssignedAccess-Trace" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-Setup" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\NBSMBLOGGER" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\PEAuthLog" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\RdrLog" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\ReadyBoot" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatformTel" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SocketHeciServer" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TCPIPLOGGER" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TileStore" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Tpm" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TPMProvisioningService" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\UBPM" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WdiContextLog" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WFP-IPsec Trace" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSession" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSessionRepro" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WinPhoneCritical" /v "Start" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogEnable" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogLevel" /t REG_DWORD /d "0" /f >> APB_Log.txt 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Credssp" /v "DebugLogLevel" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Telemetry Services
echo Disabling Telemetry Services >> APB_Log.txt
sc stop DiagTrack >> APB_Log.txt
sc config DiagTrack start= disabled >> APB_Log.txt
sc stop dmwappushservice >> APB_Log.txt
sc config dmwappushservice start= disabled >> APB_Log.txt
sc stop diagnosticshub.standardcollector.service >> APB_Log.txt
sc config diagnosticshub.standardcollector.service start= disabled >> APB_Log.txt
timeout /t 1 /nobreak > NUL

goto CompletedTelemetryOptimizations

:CompletedTelemetryOptimizations
cls
echo Completed Telemetry Optimizations
timeout /t 3 /nobreak > NUL
cls
set c=[33m
set t=[0m
set w=[95m
set y=[0m
set u=[4m
set q=[0m
echo.
echo.
echo.
echo.
echo      %w%█████%y%%c%╗%t% %w%███%y%%c%╗%t%   %w%██%y%%c%╗%t% %w%██████%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%██%y%%c%╗%t%     %w%███████%y%%c%╗%t%    %w%████████%y%%c%╗%t%%w%██%y%%c%╗%t%    %w%██%y%%c%╗%t%%w%███████%y%%c%╗%t% %w%█████%y%%c%╗%t% %w%██%y%%c%╗%t%  %w%██%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%██████%y%%c%╗%t% 
echo     %w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%%w%████%y%%c%╗%t%  %w%██%y%%c%║%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%║%t%     %w%██%y%%c%╔════╝    ╚══%t%%w%██%y%%c%╔══╝%t%%w%██%y%%c%║%t%    %w%██%y%%c%║%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%%w%██%y%%c%║%t% %w%██%y%%c%╔╝%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%
echo     %w%███████%y%%c%║%t%%w%██%y%%c%╔%t%%w%██%y%%c%╗%t% %w%██%y%%c%║%t%%w%██%y%%c%║%t%     %w%█████%y%%c%╗%t%  %w%██%y%%c%║%t%     %w%███████%y%%c%╗%t%       %w%██%y%%c%║%t%   %w%██%y%%c%║%t% %w%█%y%%c%╗%t% %w%██%y%%c%║%t%%w%█████%y%%c%╗%t%  %w%███████%y%%c%║%t%%w%█████%y%%c%╔╝%t% %w%█████%y%%c%╗%t%  %w%██████%y%%c%╔╝%t%
echo     %w%██%y%%c%╔══%t%%w%██%y%%c%║%t%%w%██%y%%c%║╚%t%%w%██%y%%c%╗%t%%w%██%y%%c%║%t%%w%██%y%%c%║%t%     %w%██%y%%c%╔══╝%t%  %w%██%y%%c%║     ╚════%t%%w%██%y%%c%║%t%       %w%██%y%%c%║%t%   %w%██%y%%c%║%t%%w%███%y%%c%╗%t%%w%██%y%%c%║%t%%w%██%y%%c%╔══╝%t%  %w%██%y%%c%╔══%t%%w%██%y%%c%║%t%%w%██%y%%c%╔═%t%%w%██%y%%c%╗%t% %w%██%y%%c%╔══╝%t%  %w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%
echo     %w%██%y%%c%║%t%  %w%██%y%%c%║%t%%w%██%y%%c%║ ╚%t%%w%████%y%%c%║╚%t%%w%██████%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%███████%y%%c%║%t%       %w%██%y%%c%║   ╚%t%%w%███%y%%c%╔%t%%w%███%y%%c%╔╝%t%%w%███████%y%%c%╗%t%%w%██%y%%c%║%t%  %w%██%y%%c%║%t%%w%██%y%%c%║%t%  %w%██%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%██%y%%c%║%t%  %w%██%y%%c%║%t%
echo     %c%╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚══════╝╚══════╝       ╚═╝    ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝%t%                                                                                                                                                        
echo                                                   %c%Created By: ancel_%t%     
echo                                                      %c%%u%Version: %Version%%q%%t%
echo.
echo %w%════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════%y%
echo.
echo.
echo.
echo.
echo.
echo                                              %w%[%y% %c%%u%1%q%%t% %w%]%y% %c%Menu%t%               %w%[%y% %c%%u%2%q%%t% %w%]%y% %c%Exit%t%
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto Menu
if '%choice%'=='2' goto Close


:Network
cls
set z=[7m
set i=[1m
set q=[0m
echo %z%Network Optimizations can cause better/worse results depending on the user, results may vary.%q%
echo.
echo %z%Would you like to Create a Restore Point before Optimizing your Network?%q%
echo.
echo %i%Yes = 1%q%
echo.
echo %i%No = 2%q%
echo.
echo %i%Go back to Menu = 3%q%
echo.
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto RP2
if '%choice%'=='2' goto NetworkTweaks
if '%choice%'=='3' goto Menu

:RP2
:: Creating Restore Point
echo Creating Restore Point
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "SystemRestorePointCreationFrequency" /t REG_DWORD /d "0" /f >> APB_Log.txt
powershell -ExecutionPolicy Bypass -Command "Checkpoint-Computer -Description 'Ancels Performance Batch' -RestorePointType 'MODIFY_SETTINGS'" >> APB_Log.txt

:NetworkTweaks
cls

:: Reset Internet
echo Resetting Internet
ipconfig /release
ipconfig /renew
ipconfig /flushdns
netsh int ip reset
netsh int ipv4 reset
netsh int ipv6 reset
netsh int tcp reset
netsh winsock reset
netsh advfirewall reset
netsh branchcache reset
netsh http flush logbuffer
timeout /t 3 /nobreak > NUL

:: Disable Network Throttling
echo Disabling Network Throttling
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Set Network Autotuning to Disabled
echo Setting Network AutoTuning to Disabled
netsh int tcp set global autotuninglevel=disabled
timeout /t 1 /nobreak > NUL

:: Disable ECN
echo Disabling Explicit Congestion Notification
netsh int tcp set global ecncapability=disabled
timeout /t 1 /nobreak > NUL

:: Enable DCA
echo Enabling Direct Cache Access
netsh int tcp set global dca=enabled
timeout /t 1 /nobreak > NUL

:: Enable NetDMA
echo Enabling Network Direct Memory Access
netsh int tcp set global netdma=enabled
timeout /t 1 /nobreak > NUL

:: Disable RSC
echo Disabling Recieve Side Coalescing
netsh int tcp set global rsc=disabled
timeout /t 1 /nobreak > NUL

:: Enable RSS
echo Enabling Recieve Side Scaling
netsh int tcp set global rss=enabled
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Ndis\Parameters" /v "RssBaseCpu" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable TCP Timestamps
echo Disabling TCP Timestamps
netsh int tcp set global timestamps=disabled
timeout /t 1 /nobreak > NUL

:: Set Initial RTO to 2ms
echo Setting Initial Retransmission Timer
netsh int tcp set global initialRto=2000
timeout /t 1 /nobreak > NUL

:: Set MTU Size to 1500
echo Setting MTU Size
netsh interface ipv4 set subinterface “Ethernet” mtu=1500 store=persistent
timeout /t 1 /nobreak > NUL

:: Disable NonSackRTTresiliency
echo Disabling Non Sack RTT Resiliency
netsh int tcp set global nonsackrttresiliency=disabled
timeout /t 1 /nobreak > NUL

:: Set Max Syn Retransmissions to 2
echo Setting Max Syn Retransmissions
netsh int tcp set global maxsynretransmissions=2
timeout /t 1 /nobreak > NUL

:: Disable MPP
echo Disabling Memory Pressure Protection
netsh int tcp set security mpp=disabled
timeout /t 1 /nobreak > NUL

:: Disable Security Profiles
echo Disabling Security Profiles
netsh int tcp set security profiles=disabled
timeout /t 1 /nobreak > NUL

:: Disable Heuristics
echo Disabling Windows Scaling Heuristics
netsh int tcp set heuristics disabled
timeout /t 1 /nobreak > NUL

:: Increase ARP Cache Size to 4096
echo Increasing ARP Cache Size
netsh int ip set global neighborcachelimit=4096
timeout /t 1 /nobreak > NUL

:: Enable CTCP
echo Enabling CTCP
netsh int tcp set supplemental Internet congestionprovider=ctcp
timeout /t 1 /nobreak > NUL

:: Disable Task Offloading
echo Disabling Task Offloading
netsh int ip set global taskoffload=disabled
timeout /t 1 /nobreak > NUL

:: Disable IPv6
echo Disabling IPv6
netsh int ipv6 set state disabled
timeout /t 1 /nobreak > NUL

:: Disable ISATAP
echo Disabling ISATAP
netsh int isatap set state disabled
timeout /t 1 /nobreak > NUL

:: Disable Teredo
echo Disabling Teredo
netsh int teredo set state disabled
timeout /t 1 /nobreak > NUL

:: Set TTL to 64
echo Configuring Time to Live
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Enable TCP Window Scaling
echo Enabling TCP Window Scaling
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Set TcpMaxDupAcks
echo Setting TcpMaxDupAcks to 2
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable SackOpts
echo Disabling TCP Selective ACKs
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Increase Maximum Port Number
echo Increasing Maximum Port Number
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Decrease Time to Wait in "TIME_WAIT" State
echo Decreasing Timed Wait Delay
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Set Network Priorities
echo Setting Network Priorities
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Adjust Sock Address Size
echo Configuring Sock Address Size
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MinSockAddrLength" /t REG_DWORD /d "16" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MaxSockAddrLength" /t REG_DWORD /d "16" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Nagle's Algorithm
echo Disabling Nagle's Algorithm
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPNoDelay" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Delivery Optimization
echo Disabling Delivery Optimization
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Auto Disconnect for Idle Connections
echo Disabling Auto Disconnect
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "4294967295" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Limit Number of SMB Sessions
echo Limiting SMB Sessions
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Oplocks
echo Disabling Oplocks
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableOplocks" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Set IRP Stack Size
echo Setting IRP Stack Size
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "20" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Sharing Violations
echo Disabling Sharing Violations
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationDelay" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationRetries" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Get the Sub ID of the Network Adapter
for /f %%n in ('Reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}" /v "*SpeedDuplex" /s ^| findstr  "HKEY"') do (

:: Disable NIC Power Savings
echo Disabling NIC Power Savings
reg add "%%n" /v "AutoPowerSaveModeEnabled" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "AutoDisableGigabit" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "AdvancedEEE" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "DisableDelayedPowerUp" /t REG_SZ /d "2" /f >> APB_Log.txt
reg add "%%n" /v "*EEE" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "EEE" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "EnablePME" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "EEELinkAdvertisement" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "EnableSavePowerNow" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "EnablePowerManagement" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "EnableDynamicPowerGating" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "EnableConnectedPowerGating" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "EnableWakeOnLan" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "GigaLite" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "NicAutoPowerSaver" /t REG_SZ /d "2" /f >> APB_Log.txt
reg add "%%n" /v "PowerDownPll" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "PowerSavingMode" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "SmartPowerDownEnable" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "S5NicKeepOverrideMacAddrV2" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "S5WakeOnLan" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "ULPMode" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "WakeOnDisconnect" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "*WakeOnPattern" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "WakeOnLink" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "WolShutdownLinkSpeed" /t REG_SZ /d "2" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Jumbo Frame
echo Disabling Jumbo Frame
reg add "%%n" /v "JumboPacket" /t REG_SZ /d "1514" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Configure Receive/Transmit Buffers
echo Configuring Buffer Sizes
reg add "%%n" /v "TransmitBuffers" /t REG_SZ /d "4096" /f >> APB_Log.txt
reg add "%%n" /v "ReceiveBuffers" /t REG_SZ /d "512" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Configure Offloads
echo Configuring Offloads
reg add "%%n" /v "IPChecksumOffloadIPv4" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "LsoV1IPv4" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "LsoV2IPv4" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "LsoV2IPv6" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "PMARPOffload" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "PMNSOffload" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "TCPChecksumOffloadIPv4" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "TCPChecksumOffloadIPv6" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "UDPChecksumOffloadIPv6" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "UDPChecksumOffloadIPv4" /t REG_SZ /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Enable RSS in NIC
echo Enabling RSS in NIC
reg add "%%n" /v "RSS" /t REG_SZ /d "1" /f >> APB_Log.txt
reg add "%%n" /v "*NumRssQueues" /t REG_SZ /d "2" /f >> APB_Log.txt
reg add "%%n" /v "RSSProfile" /t REG_SZ /d "3" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Flow Control
echo Disabling Flow Control
reg add "%%n" /v "*FlowControl" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "FlowControlCap" /t REG_SZ /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Remove Interrupt Delays
echo Removing Interrupt Delays
reg add "%%n" /v "TxIntDelay" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "TxAbsIntDelay" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "RxIntDelay" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "RxAbsIntDelay" /t REG_SZ /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Remove Adapter Notification
echo Removing Adapter Notification Sending
reg add "%%n" /v "FatChannelIntolerant" /t REG_SZ /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Interrupt Moderation
echo Disabling Interrupt Moderation
reg add "%%n" /v "*InterruptModeration" /t REG_SZ /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL
)

:: Enable WeakHost Send and Recieve (melodytheneko)
echo Enabling WH Send and Recieve
powershell "Get-NetAdapter -IncludeHidden | Set-NetIPInterface -WeakHostSend Enabled -WeakHostReceive Enabled -ErrorAction SilentlyContinue"
timeout /t 1 /nobreak > NUL

goto CompletedNetworkOptimizations

:CompletedNetworkOptimizations
cls
echo Completed Network Optimizations
timeout /t 3 /nobreak > NUL
cls
set c=[33m
set t=[0m
set w=[95m
set y=[0m
set u=[4m
set q=[0m
echo.
echo.
echo.
echo.
echo      %w%█████%y%%c%╗%t% %w%███%y%%c%╗%t%   %w%██%y%%c%╗%t% %w%██████%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%██%y%%c%╗%t%     %w%███████%y%%c%╗%t%    %w%████████%y%%c%╗%t%%w%██%y%%c%╗%t%    %w%██%y%%c%╗%t%%w%███████%y%%c%╗%t% %w%█████%y%%c%╗%t% %w%██%y%%c%╗%t%  %w%██%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%██████%y%%c%╗%t% 
echo     %w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%%w%████%y%%c%╗%t%  %w%██%y%%c%║%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%║%t%     %w%██%y%%c%╔════╝    ╚══%t%%w%██%y%%c%╔══╝%t%%w%██%y%%c%║%t%    %w%██%y%%c%║%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%%w%██%y%%c%║%t% %w%██%y%%c%╔╝%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%
echo     %w%███████%y%%c%║%t%%w%██%y%%c%╔%t%%w%██%y%%c%╗%t% %w%██%y%%c%║%t%%w%██%y%%c%║%t%     %w%█████%y%%c%╗%t%  %w%██%y%%c%║%t%     %w%███████%y%%c%╗%t%       %w%██%y%%c%║%t%   %w%██%y%%c%║%t% %w%█%y%%c%╗%t% %w%██%y%%c%║%t%%w%█████%y%%c%╗%t%  %w%███████%y%%c%║%t%%w%█████%y%%c%╔╝%t% %w%█████%y%%c%╗%t%  %w%██████%y%%c%╔╝%t%
echo     %w%██%y%%c%╔══%t%%w%██%y%%c%║%t%%w%██%y%%c%║╚%t%%w%██%y%%c%╗%t%%w%██%y%%c%║%t%%w%██%y%%c%║%t%     %w%██%y%%c%╔══╝%t%  %w%██%y%%c%║     ╚════%t%%w%██%y%%c%║%t%       %w%██%y%%c%║%t%   %w%██%y%%c%║%t%%w%███%y%%c%╗%t%%w%██%y%%c%║%t%%w%██%y%%c%╔══╝%t%  %w%██%y%%c%╔══%t%%w%██%y%%c%║%t%%w%██%y%%c%╔═%t%%w%██%y%%c%╗%t% %w%██%y%%c%╔══╝%t%  %w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%
echo     %w%██%y%%c%║%t%  %w%██%y%%c%║%t%%w%██%y%%c%║ ╚%t%%w%████%y%%c%║╚%t%%w%██████%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%███████%y%%c%║%t%       %w%██%y%%c%║   ╚%t%%w%███%y%%c%╔%t%%w%███%y%%c%╔╝%t%%w%███████%y%%c%╗%t%%w%██%y%%c%║%t%  %w%██%y%%c%║%t%%w%██%y%%c%║%t%  %w%██%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%██%y%%c%║%t%  %w%██%y%%c%║%t%
echo     %c%╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚══════╝╚══════╝       ╚═╝    ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝%t%                                                                                                                                                        
echo                                                   %c%Created By: ancel_%t%     
echo                                                      %c%%u%Version: %Version%%q%%t%
echo.
echo %w%════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════%y%
echo.
echo.
echo.
echo.
echo.
echo                                              %w%[%y% %c%%u%1%q%%t% %w%]%y% %c%Menu%t%               %w%[%y% %c%%u%2%q%%t% %w%]%y% %c%Exit%t%
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto Menu
if '%choice%'=='2' goto Close


:DebloatWindows
cls

chcp 65001 >nul 2>&1
cls
set c=[33m
set t=[0m
set w=[95m
set y=[0m
set u=[4m
set q=[0m
echo.
echo.
echo.
echo.
echo      %w%█████%y%%c%╗%t% %w%███%y%%c%╗%t%   %w%██%y%%c%╗%t% %w%██████%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%██%y%%c%╗%t%     %w%███████%y%%c%╗%t%    %w%████████%y%%c%╗%t%%w%██%y%%c%╗%t%    %w%██%y%%c%╗%t%%w%███████%y%%c%╗%t% %w%█████%y%%c%╗%t% %w%██%y%%c%╗%t%  %w%██%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%██████%y%%c%╗%t% 
echo     %w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%%w%████%y%%c%╗%t%  %w%██%y%%c%║%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%║%t%     %w%██%y%%c%╔════╝    ╚══%t%%w%██%y%%c%╔══╝%t%%w%██%y%%c%║%t%    %w%██%y%%c%║%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%%w%██%y%%c%║%t% %w%██%y%%c%╔╝%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%
echo     %w%███████%y%%c%║%t%%w%██%y%%c%╔%t%%w%██%y%%c%╗%t% %w%██%y%%c%║%t%%w%██%y%%c%║%t%     %w%█████%y%%c%╗%t%  %w%██%y%%c%║%t%     %w%███████%y%%c%╗%t%       %w%██%y%%c%║%t%   %w%██%y%%c%║%t% %w%█%y%%c%╗%t% %w%██%y%%c%║%t%%w%█████%y%%c%╗%t%  %w%███████%y%%c%║%t%%w%█████%y%%c%╔╝%t% %w%█████%y%%c%╗%t%  %w%██████%y%%c%╔╝%t%
echo     %w%██%y%%c%╔══%t%%w%██%y%%c%║%t%%w%██%y%%c%║╚%t%%w%██%y%%c%╗%t%%w%██%y%%c%║%t%%w%██%y%%c%║%t%     %w%██%y%%c%╔══╝%t%  %w%██%y%%c%║     ╚════%t%%w%██%y%%c%║%t%       %w%██%y%%c%║%t%   %w%██%y%%c%║%t%%w%███%y%%c%╗%t%%w%██%y%%c%║%t%%w%██%y%%c%╔══╝%t%  %w%██%y%%c%╔══%t%%w%██%y%%c%║%t%%w%██%y%%c%╔═%t%%w%██%y%%c%╗%t% %w%██%y%%c%╔══╝%t%  %w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%
echo     %w%██%y%%c%║%t%  %w%██%y%%c%║%t%%w%██%y%%c%║ ╚%t%%w%████%y%%c%║╚%t%%w%██████%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%███████%y%%c%║%t%       %w%██%y%%c%║   ╚%t%%w%███%y%%c%╔%t%%w%███%y%%c%╔╝%t%%w%███████%y%%c%╗%t%%w%██%y%%c%║%t%  %w%██%y%%c%║%t%%w%██%y%%c%║%t%  %w%██%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%██%y%%c%║%t%  %w%██%y%%c%║%t%
echo     %c%╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚══════╝╚══════╝       ╚═╝    ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝%t%                                                                                                                                                        
echo                                                   %c%Created By: ancel_%t%     
echo                                                      %c%%u%Version: %Version%%q%%t%
echo.
echo %w%════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════%y%
echo.
echo.
echo.
echo                          %w%[%y% %c%%u%1%q%%t% %w%]%y% %c%Remove Powershell Packages%t%                  %w%[%y% %c%%u%2%q%%t% %w%]%y% %c%Disable Cortana%t%      
echo. 
echo.
echo                          %w%[%y% %c%%u%3%q%%t% %w%]%y% %c%Disable Unnecessary Services%t%                %w%[%y% %c%%u%4%q%%t% %w%]%y% %c%Disable OneDrive%t%
echo.
echo.
echo                          %w%[%y% %c%%u%5%q%%t% %w%]%y% %c%PC Cleaner%t%                                  %w%[%y% %c%%u%6%q%%t% %w%]%y% %c%Go Back to Menu%t%                                                          
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto PowerShellPackages
if '%choice%'=='2' goto DisableCortana
if '%choice%'=='3' goto UnnecessaryServicesDisable  
if '%choice%'=='4' goto DisableOneDrive
if '%choice%'=='5' goto PCCleaner
if '%choice%'=='6' goto Menu                  

:PowerShellPackages
cls
echo Removing Unnecessary Powershell Packages
PowerShell -Command "Get-AppxPackage -allusers *3DBuilder* | Remove-AppxPackage" >> APB_Log.txt
PowerShell -Command "Get-AppxPackage -allusers *bing* | Remove-AppxPackage" >> APB_Log.txt
PowerShell -Command "Get-AppxPackage -allusers *bingfinance* | Remove-AppxPackage" >> APB_Log.txt
PowerShell -Command "Get-AppxPackage -allusers *bingsports* | Remove-AppxPackage" >> APB_Log.txt
PowerShell -Command "Get-AppxPackage -allusers *BingWeather* | Remove-AppxPackage" >> APB_Log.txt
PowerShell -Command "Get-AppxPackage -allusers *CommsPhone* | Remove-AppxPackage" >> APB_Log.txt
PowerShell -Command "Get-AppxPackage -allusers *Drawboard PDF* | Remove-AppxPackage" >> APB_Log.txt
PowerShell -Command "Get-AppxPackage -allusers *Facebook* | Remove-AppxPackage" >> APB_Log.txt
PowerShell -Command "Get-AppxPackage -allusers *Getstarted* | Remove-AppxPackage" >> APB_Log.txt
PowerShell -Command "Get-AppxPackage -allusers *Microsoft.Messaging* | Remove-AppxPackage" >> APB_Log.txt
PowerShell -Command "Get-AppxPackage -allusers *MicrosoftOfficeHub* | Remove-AppxPackage" >> APB_Log.txt
PowerShell -Command "Get-AppxPackage -allusers *Office.OneNote* | Remove-AppxPackage" >> APB_Log.txt
PowerShell -Command "Get-AppxPackage -allusers *OneNote* | Remove-AppxPackage" >> APB_Log.txt
PowerShell -Command "Get-AppxPackage -allusers *people* | Remove-AppxPackage" >> APB_Log.txt
PowerShell -Command "Get-AppxPackage -allusers *SkypeApp* | Remove-AppxPackage" >> APB_Log.txt
PowerShell -Command "Get-AppxPackage -allusers *solit* | Remove-AppxPackage" >> APB_Log.txt
PowerShell -Command "Get-AppxPackage -allusers *Sway* | Remove-AppxPackage" >> APB_Log.txt
PowerShell -Command "Get-AppxPackage -allusers *Twitter* | Remove-AppxPackage" >> APB_Log.txt
PowerShell -Command "Get-AppxPackage -allusers *WindowsAlarms* | Remove-AppxPackage" >> APB_Log.txt
PowerShell -Command "Get-AppxPackage -allusers *WindowsPhone* | Remove-AppxPackage" >> APB_Log.txt
PowerShell -Command "Get-AppxPackage -allusers *WindowsMaps* | Remove-AppxPackage" >> APB_Log.txt
PowerShell -Command "Get-AppxPackage -allusers *WindowsFeedbackHub* | Remove-AppxPackage" >> APB_Log.txt
PowerShell -Command "Get-AppxPackage -allusers *WindowsSoundRecorder* | Remove-AppxPackage" >> APB_Log.txt
PowerShell -Command "Get-AppxPackage -allusers *windowscommunicationsapps* | Remove-AppxPackage" >> APB_Log.txt
PowerShell -Command "Get-AppxPackage -allusers *zune* | Remove-AppxPackage" >> APB_Log.txt
timeout /t 5 /nobreak > NUL

goto DebloatWindows

:UnnecessaryServicesDisable
cls
echo Disabling Unnecessary Services
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TapiSrv" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache3.0.0.0" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WpcMonSvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SEMgrSvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PNRPsvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WEPHOSTSVC" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\p2psvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\p2pimsvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PhoneSvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /t REG_DWORD /d "3" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SensorDataService" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SensrSvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\perceptionsimulation" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\StiSvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\autotimesvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdatem" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ALG" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\QWAVE" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\icssvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DusmSvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdate" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SensorService" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\shpamsvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\svsvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SysMain" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MSiSCSI" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CscService" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ssh-agent" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AppReadiness" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tzautoupdate" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NfsClnt" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wisvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\defragsvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedRealitySvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RetailDemo" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lltdsvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TrkWks" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CryptSvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DPS" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHost" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushsvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TroubleshootingSvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DsSvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FrameServer" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\InstallService" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\OSRSS" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\sedsvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SENS" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TabletInputService" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Themes" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UnistoreSvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MessagingService" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CDPUserSvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BcastDVRUserService" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UserDataSvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\cbdhsvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CaptureService" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "AllowPrelaunch" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v "AllowTabPreloading" /t REG_DWORD /d "0" /f >> APB_Log.txt

timeout /t 5 /nobreak > NUL

goto DebloatWindows

:DisableCortana
cls
echo Disabling Cortana
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "0" /f >> APB_Log.txt
Powershell -Command "Get-appxpackage -allusers *Microsoft.549981C3F5F10* | Remove-AppxPackage" >> APB_Log.txt
timeout /t 5 /nobreak > NUL

goto DebloatWindows

:DisableOneDrive
cls
echo Disabling OneDrive
start /wait "" "%SYSTEMROOT%\SYSWOW64\ONEDRIVESETUP.EXE" /UNINSTALL
rd C:\OneDriveTemp /q /s >> APB_Log.txt
rd "%USERPROFILE%\OneDrive" /q /s >> APB_Log.txt
rd "%LOCALAPPDATA%\Microsoft\OneDrive" /q /s >> APB_Log.txt
rd "%PROGRAMDATA%\Microsoft OneDrive" /q /s >> APB_Log.txt
reg add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v "Attributes" /t REG_DWORD /d "0" >> APB_Log.txt
reg add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v "Attributes" /t REG_DWORD /d "0" >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSync" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableMeteredNetworkFileSync" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableLibrariesDefaultSaveToOneDrive" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 5 /nobreak > NUL

goto DebloatWindows

:PCCleaner
cls
echo Cleaning PC...
del /s /f /q c:\windows\temp. >> APB_Log.txt
del /s /f /q C:\WINDOWS\Prefetch >> APB_Log.txt
del /s /f /q %temp%. >> APB_Log.txt
del /s /f /q %systemdrive%\*.tmp >> APB_Log.txt
del /s /f /q %systemdrive%\*._mp >> APB_Log.txt
del /s /f /q %systemdrive%\*.log >> APB_Log.txt
del /s /f /q %systemdrive%\*.gid >> APB_Log.txt
del /s /f /q %systemdrive%\*.chk >> APB_Log.txt
del /s /f /q %systemdrive%\*.old >> APB_Log.txt
del /s /f /q %systemdrive%\recycled\*.* >> APB_Log.txt
del /s /f /q %systemdrive%\$Recycle.Bin\*.* >> APB_Log.txt
del /s /f /q %windir%\*.bak >> APB_Log.txt
del /s /f /q %windir%\prefetch\*.* >> APB_Log.txt
del /s /f /q %LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*.db >> APB_Log.txt
del /s /f /q %LocalAppData%\Microsoft\Windows\Explorer\*.db >> APB_Log.txt
del /f /q %SystemRoot%\Logs\CBS\CBS.log >> APB_Log.txt
del /f /q %SystemRoot%\Logs\DISM\DISM.log >> APB_Log.txt
deltree /y c:\windows\tempor~1 >> APB_Log.txt
deltree /y c:\windows\temp >> APB_Log.txt
deltree /y c:\windows\tmp >> APB_Log.txt
deltree /y c:\windows\ff*.tmp >> APB_Log.txt
deltree /y c:\windows\history >> APB_Log.txt
deltree /y c:\windows\cookies >> APB_Log.txt
deltree /y c:\windows\recent >> APB_Log.txt
deltree /y c:\windows\spool\printers >> APB_Log.txt
cls
timeout /t 10 /nobreak > NUL

goto DebloatWindows

:Other

cls
set c=[33m
set t=[0m
set w=[95m
set y=[0m
set u=[4m
set q=[0m
echo.
echo.
echo.
echo.
echo      %w%█████%y%%c%╗%t% %w%███%y%%c%╗%t%   %w%██%y%%c%╗%t% %w%██████%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%██%y%%c%╗%t%     %w%███████%y%%c%╗%t%    %w%████████%y%%c%╗%t%%w%██%y%%c%╗%t%    %w%██%y%%c%╗%t%%w%███████%y%%c%╗%t% %w%█████%y%%c%╗%t% %w%██%y%%c%╗%t%  %w%██%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%██████%y%%c%╗%t% 
echo     %w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%%w%████%y%%c%╗%t%  %w%██%y%%c%║%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%║%t%     %w%██%y%%c%╔════╝    ╚══%t%%w%██%y%%c%╔══╝%t%%w%██%y%%c%║%t%    %w%██%y%%c%║%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%%w%██%y%%c%║%t% %w%██%y%%c%╔╝%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%
echo     %w%███████%y%%c%║%t%%w%██%y%%c%╔%t%%w%██%y%%c%╗%t% %w%██%y%%c%║%t%%w%██%y%%c%║%t%     %w%█████%y%%c%╗%t%  %w%██%y%%c%║%t%     %w%███████%y%%c%╗%t%       %w%██%y%%c%║%t%   %w%██%y%%c%║%t% %w%█%y%%c%╗%t% %w%██%y%%c%║%t%%w%█████%y%%c%╗%t%  %w%███████%y%%c%║%t%%w%█████%y%%c%╔╝%t% %w%█████%y%%c%╗%t%  %w%██████%y%%c%╔╝%t%
echo     %w%██%y%%c%╔══%t%%w%██%y%%c%║%t%%w%██%y%%c%║╚%t%%w%██%y%%c%╗%t%%w%██%y%%c%║%t%%w%██%y%%c%║%t%     %w%██%y%%c%╔══╝%t%  %w%██%y%%c%║     ╚════%t%%w%██%y%%c%║%t%       %w%██%y%%c%║%t%   %w%██%y%%c%║%t%%w%███%y%%c%╗%t%%w%██%y%%c%║%t%%w%██%y%%c%╔══╝%t%  %w%██%y%%c%╔══%t%%w%██%y%%c%║%t%%w%██%y%%c%╔═%t%%w%██%y%%c%╗%t% %w%██%y%%c%╔══╝%t%  %w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%
echo     %w%██%y%%c%║%t%  %w%██%y%%c%║%t%%w%██%y%%c%║ ╚%t%%w%████%y%%c%║╚%t%%w%██████%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%███████%y%%c%║%t%       %w%██%y%%c%║   ╚%t%%w%███%y%%c%╔%t%%w%███%y%%c%╔╝%t%%w%███████%y%%c%╗%t%%w%██%y%%c%║%t%  %w%██%y%%c%║%t%%w%██%y%%c%║%t%  %w%██%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%██%y%%c%║%t%  %w%██%y%%c%║%t%
echo     %c%╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚══════╝╚══════╝       ╚═╝    ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝%t%                                                                                                                                                        
echo                                                   %c%Created By: ancel_%t%     
echo                                                      %c%%u%Version: %Version%%q%%t%
echo.
echo %w%════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════%y%
echo.
echo.
echo.
echo                               %w%[%y% %c%%u%1%q%%t% %w%]%y% %c%Disable Drivers%t%                  %w%[%y% %c%%u%2%q%%t% %w%]%y% %c%Power Plan%t%      
echo. 
echo.
echo                               %w%[%y% %c%%u%3%q%%t% %w%]%y% %c%KBoost%t%                           %w%[%y% %c%%u%4%q%%t% %w%]%y% %c%Disable Devices%t%
echo.
echo.
echo                               %w%[%y% %c%%u%5%q%%t% %w%]%y% %c%Run OOSU%t%                         %w%[%y% %c%%u%6%q%%t% %w%]%y% %c%Go Back to Menu%t%      
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto DisableDrivers
if '%choice%'=='2' goto PowerPlan
if '%choice%'=='3' goto KBoost
if '%choice%'=='4' goto DisableDevices
if '%choice%'=='5' goto RunOOSU
if '%choice%'=='6' goto Menu

:DisableDrivers
cls
set z=[7m
set i=[1m
set q=[0m
echo %z%Disabling Drivers are very risky. This can break certain things within windows, do you wish to Continue?%q%
echo.
echo %i%Yes = 1%q%
echo.
echo %i%No = 2%q%
echo.
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto DisableDriversContinue
if '%choice%'=='2' goto Other

:DisableDriversContinue
cls
echo Disabling Drivers
reg add "HKLM\SYSTEM\CurrentControlSet\Services\acpipagr" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AcpiPmi" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Beep" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CAD" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CLFS" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CSC" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\luafv" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RasAcd" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Rasl2tp" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RasPppoe" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RasSstp" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpipreg" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dam" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wanarpv6" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PEAUTH" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\QWAVEdrv" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\cdrom" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\fileinfo" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FileCrypt" /v "Start" /t REG_DWORD /d "4" /f >> APB_Log.txt
timeout /t 10 /nobreak > NUL

goto Other

:PowerPlan
cls
echo Applying Ancels Power Plan
:: Import Ancels Power Plan
curl -g -k -L -# -o "C:\Ancels Power Plan.pow" "https://github.com/ancel1x/Ancels-Performance-Batch/raw/main/bin/Ancels_Power_Plan.pow" >> APB_Log.txt
powercfg -import "C:\Ancels Power Plan.pow" 11111111-1111-1111-1111-111111111111 >> APB_Log.txt
powercfg -setactive 11111111-1111-1111-1111-111111111111 >> APB_Log.txt
timeout /t 3 /nobreak > NUL

echo Deleting other Power Plans
:: Delete Balanced Power Plan
powercfg -delete 381b4222-f694-41f0-9685-ff5bb260df2e >> APB_Log.txt

:: Delete Power Saver Power Plan
powercfg -delete a1841308-3541-4fab-bc81-f71556f20b4a >> APB_Log.txt

:: Delete High Performance Power Plan
powercfg -delete 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c >> APB_Log.txt

:: Delete Ultimate Performance Power Plan
powercfg -delete e9a42b02-d5df-448d-aa00-03f14749eb61 >> APB_Log.txt

:: Delete AMD Ryzen Balanced Power Plan
powercfg -delete 9897998c-92de-4669-853f-b7cd3ecb2790 >> APB_Log.txt
timeout /t 3 /nobreak > NUL

goto Other

:KBoost
cls
set z=[7m
set i=[1m
set q=[0m
echo %z%Would you like to Enable/Disable KBoost?%q%
echo.
echo %i%Enable = 1%q%
echo.
echo %i%Disable = 2%q%
echo.
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto EnableKBoost
if '%choice%'=='2' goto DisableKBoost

:EnableKBoost
cls
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PerfLevelSrc" /t REG_DWORD /d "2222" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PowerMizerEnable" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PowerMizerLevel" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PowerMizerLevelAC" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 3 /nobreak > NUL

goto Other

:DisableKBoost
cls
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PerfLevelSrc" /f >> APB_Log.txt
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PowerMizerEnable" /f >> APB_Log.txt
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PowerMizerLevel" /f >> APB_Log.txt
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PowerMizerLevelAC" /f >> APB_Log.txt
timeout /t 3 /nobreak > NUL

goto Other

:DisableDevices
cls
set z=[7m
set i=[1m
set q=[0m
echo %z%Disabling Devices are very risky. This can break certain things within windows, do you wish to Continue?%q%
echo.
echo %i%Yes = 1%q%
echo.
echo %i%No = 2%q%
echo.
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto DisableDevicesContinue
if '%choice%'=='2' goto Other

:DisableDevicesContinue
cls
echo Disabling Devices

:: Install DevManView
curl -g -k -L -# -o "C:\Windows\System32\DevManView.exe" "https://github.com/ancel1x/Ancels-Performance-Batch/raw/main/bin/DevManView.exe" >> APB_Log.txt
timeout /t 3 /nobreak > NUL

:: Disable Devices through DevManView
DevManView.exe /disable "High Precision Event Timer"
DevManView.exe /disable "Microsoft GS Wavetable Synth"
DevManView.exe /disable "Microsoft RRAS Root Enumerator"
DevManView.exe /disable "Intel Management Engine"
DevManView.exe /disable "Intel Management Engine Interface"
DevManView.exe /disable "Intel SMBus"
DevManView.exe /disable "SM Bus Controller"
DevManView.exe /disable "Amdlog"
DevManView.exe /disable "AMD PSP"
DevManView.exe /disable "System Speaker"
DevManView.exe /disable "Composite Bus Enumerator"
DevManView.exe /disable "Microsoft Virtual Drive Enumerator"
DevManView.exe /disable "Microsoft Hyper-V Virtualization Infrastructure Driver"
DevManView.exe /disable "NDIS Virtual Network Adapter Enumerator"
DevManView.exe /disable "Remote Desktop Device Redirector Bus"
DevManView.exe /disable "UMBus Root Bus Enumerator"
DevManView.exe /disable "WAN Miniport (IP)"
DevManView.exe /disable "WAN Miniport (IKEv2)"
DevManView.exe /disable "WAN Miniport (IPv6)"
DevManView.exe /disable "WAN Miniport (L2TP)"
DevManView.exe /disable "WAN Miniport (PPPOE)"
DevManView.exe /disable "WAN Miniport (PPTP)"
DevManView.exe /disable "WAN Miniport (SSTP)"
DevManView.exe /disable "WAN Miniport (Network Monitor)"
timeout /t 3 /nobreak > NUL

:: Disable Monitor Sound
cls
set z=[7m
set i=[1m
set q=[0m
echo %z%Do you use Monitor Sound?%q%
echo.
echo %i%Yes = 1%q%
echo.
echo %i%No = 2%q%
echo.
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto PrinterDevice
if '%choice%'=='2' goto DisableMonitorSound

:DisableMonitorSound
cls
DevManView.exe /disable "High Definition Audio Controller"
timeout /t 3 /nobreak > NUL

:: Disable Printer
:PrinterDevice
cls
set z=[7m
set i=[1m
set q=[0m
echo %z%Do you use a Printer?%q%
echo.
echo %i%Yes = 1%q%
echo.
echo %i%No = 2%q%
echo.
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto FinishedDevices
if '%choice%'=='2' goto DisablePrinterDevice

:DisablePrinterDevice
cls 
DevManView.exe /disable "Root Print Queue"
timeout /t 3 /nobreak > NUL

goto FinishedDevices

:FinishedDevices
cls
echo Finished Disabling Devices
timeout /t 5 /nobreak > NUL

goto Other

:RunOOSU
cls
:: Install O&O Shutup and Import Config
powershell Invoke-WebRequest "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -OutFile "%temp%\OOSU10.exe"
curl -g -k -L -# -o "C:\ANCELOOSUIMPORT.cfg" "https://github.com/ancel1x/Ancels-Performance-Batch/raw/main/bin/ANCELOOSUIMPORT.cfg"
start "" /wait "%temp%\OOSU10.exe" "C:\ANCELOOSUIMPORT.cfg" >> APB_Log.txt
cls
echo OOSU Ran Successfully
timeout /t 5 /nobreak > NUL

goto Other

:Close
cls 
exit