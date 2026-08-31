@echo off
setlocal
title Windows Performance Diagnostics - WinRE Boot-Failure Puller
echo ============================================================
echo  Windows Performance Diagnostics - WinRE Boot-Failure Puller
echo ============================================================
echo.
echo Run this from a Command Prompt in WinRE/WinPE on a machine
echo that will not boot (Advanced options - Command Prompt, or a
echo bootable WinPE USB). It copies Startup Repair, boot log, CBS,
echo setup and DISM evidence into a folder on the PE drive.
echo Read-only against the broken system drive.
echo.
echo The collector's live -CollectBootFailureLogs stage is the
echo alternative on machines that still boot.
echo.

set "SYSDRIVE="
set /p SYSDRIVE="System drive letter (where Windows is installed, usually C): "
if "%SYSDRIVE%"=="" goto :bad_drive
if not exist "%SYSDRIVE%:\Windows" goto :bad_drive

set "PEDRIVE="
set /p PEDRIVE="PE drive letter (your USB / recovery media, usually D or E): "
if "%PEDRIVE%"=="" goto :bad_drive
if not exist "%PEDRIVE%:\*" goto :bad_drive

set "OUTDIR=%PEDRIVE%:\bootfailure-evidence"
set "OUTSUFFIX="
set /a TRY=0
:find_dir
if not exist "%OUTDIR%%OUTSUFFIX%" goto :dir_ok
set /a TRY+=1
set "OUTSUFFIX=-%TRY%"
goto :find_dir
:dir_ok
set "OUTDIR=%OUTDIR%%OUTSUFFIX%"
mkdir "%OUTDIR%"
echo.
echo Output folder: %OUTDIR%
echo ============================================================ > "%OUTDIR%\collection-status.txt"
echo WinRE boot-failure evidence - %date% %time% >> "%OUTDIR%\collection-status.txt"
echo [OK] System drive %SYSDRIVE%:\ - Windows found >> "%OUTDIR%\collection-status.txt"

if exist "%SYSDRIVE%:\Windows\System32\LogFiles\Srt\SrtTrail.txt" goto :srt_yes
echo [MISS] SrtTrail.txt (Startup Repair trail) not found >> "%OUTDIR%\collection-status.txt"
goto :bootlog
:srt_yes
copy /y "%SYSDRIVE%:\Windows\System32\LogFiles\Srt\SrtTrail.txt" "%OUTDIR%" >nul
echo [OK] SrtTrail.txt copied >> "%OUTDIR%\collection-status.txt"

:bootlog
if exist "%SYSDRIVE%:\Windows\ntbtlog.txt" goto :ntbt_yes
echo [MISS] ntbtlog.txt not found (boot logging was not enabled for the failures) >> "%OUTDIR%\collection-status.txt"
goto :cbs
:ntbt_yes
copy /y "%SYSDRIVE%:\Windows\ntbtlog.txt" "%OUTDIR%" >nul
echo [OK] ntbtlog.txt copied >> "%OUTDIR%\collection-status.txt"

:cbs
echo [INFO] Copying CBS logs (100 MB cap per file) >> "%OUTDIR%\collection-status.txt"
robocopy "%SYSDRIVE%:\Windows\Logs\CBS" "%OUTDIR%\CBS" /MAX:104857600 /NFL /NDL /NJH /NJS >nul 2>&1
if errorlevel 8 echo [WARN] CBS copy failed - see robocopy exit code above >> "%OUTDIR%\collection-status.txt"

echo [INFO] Copying Panther setup logs (100 MB cap per file) >> "%OUTDIR%\collection-status.txt"
robocopy "%SYSDRIVE%:\Windows\Panther" "%OUTDIR%\Panther" /MAX:104857600 /NFL /NDL /NJH /NJS >nul 2>&1
if errorlevel 8 echo [WARN] Panther copy failed - see robocopy exit code above >> "%OUTDIR%\collection-status.txt"

echo [INFO] Copying DISM logs (100 MB cap per file) >> "%OUTDIR%\collection-status.txt"
robocopy "%SYSDRIVE%:\Windows\Logs\DISM" "%OUTDIR%\DISM" /MAX:104857600 /NFL /NDL /NJH /NJS >nul 2>&1
if errorlevel 8 echo [WARN] DISM copy failed - see robocopy exit code above >> "%OUTDIR%\collection-status.txt"

echo [INFO] Recording crash-dump listings (dumps are NOT copied here) >> "%OUTDIR%\collection-status.txt"
dir "%SYSDRIVE%:\Windows\Minidump" > "%OUTDIR%\minidump-listing.txt" 2>nul
dir "%SYSDRIVE%:\Windows\MEMORY.DMP" >> "%OUTDIR%\minidump-listing.txt" 2>nul

echo.
echo ============================================================
echo  Optional: enable boot logging for the NEXT boot attempt
echo ============================================================
echo  bcdedit /set {default} bootlog yes
echo  This is a persistent change to the boot configuration. It helps
echo  the next failed boot leave an ntbtlog.txt behind. Revert with:
echo  bcdedit /deletevalue {default} bootlog
set /p ENABLEBOOTLOG="Enable boot logging for the next boot? (y/N): "
if /i "%ENABLEBOOTLOG%"=="y" goto :enable_bootlog
echo [SKIP] Boot logging left unchanged >> "%OUTDIR%\collection-status.txt"
goto :done

:enable_bootlog
bcdedit /set {default} bootlog yes
if errorlevel 1 goto :bcdedit_failed
echo [OK] Boot logging enabled for the next boot >> "%OUTDIR%\collection-status.txt"
goto :done

:bcdedit_failed
echo [WARN] bcdedit failed - see the screen output above >> "%OUTDIR%\collection-status.txt"

:done
echo.
echo ============================================================
echo  Done. Evidence is in:  %OUTDIR%
echo  Status log:            %OUTDIR%\collection-status.txt
echo ============================================================
echo.
if not "%CI%"=="true" pause
endlocal
