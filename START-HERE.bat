@echo off
setlocal
pushd "%~dp0"

set "OUTDIR=C:\Temp\WPD-Case"
set "LOG=%OUTDIR%\diagnostics-run.log"

title Windows Performance Diagnostics Toolkit - START HERE

echo ============================================================
echo  Windows Performance Diagnostics Toolkit - START HERE
echo ============================================================
echo.

REM ---- pre-flight: the collector must exist (Defender may strip downloaded .ps1) ----
if not exist "%~dp0src\Invoke-WindowsPerformanceDiagnostics.ps1" (
    echo [ERROR] src\Invoke-WindowsPerformanceDiagnostics.ps1 was not found.
    echo.
    echo Windows Security may have removed the downloaded script (Mark of the Web).
    echo Fix it per README-FIRST.txt:
    echo   1. Right-click the zip in Explorer - Properties - check UNBLOCK - Extract
    echo   2. If the .ps1 is gone after extraction, restore it from Windows Security
    echo      - Virus and threat protection - Protection history
    echo   3. Then run:  powershell -Command "Unblock-File -Path '.\src\Invoke-WindowsPerformanceDiagnostics.ps1'"
    goto :end
)

REM ---- admin check + UAC self-elevation ----
net session >nul 2>&1
if %errorlevel% neq 0 (
    if "%CI%"=="true" (
        echo [ERROR] CI runner is not elevated; the elevated path cannot be tested here.
        exit /b 1
    )
    echo Requesting administrator privileges (UAC)...
    echo.
    powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
echo Running with administrator privileges.
echo.

set "CHOICE=%~1"
if "%CHOICE%"=="" (
    echo Choose an option:
    echo.
    echo   1 - Full collection + WPR trace         (recommended)
    echo   2 - Basic collection                   (no WPR)
    echo   3 - Full + WPR + Defender recording    (needs DefenderPerformance module)
    echo   4 - Plan preview only                  (writes plan, collects nothing)
    echo   5 - Exit
    echo.
    set /p CHOICE="Enter 1-5: "
)

if "%CHOICE%"=="1" goto :opt_full
if "%CHOICE%"=="2" goto :opt_basic
if "%CHOICE%"=="3" goto :opt_defender
if "%CHOICE%"=="4" goto :opt_plan
if "%CHOICE%"=="5" exit /b 0
echo [ERROR] Invalid choice: %CHOICE%
echo.
goto :end

:opt_full
set "EXTRA=-CaptureWpr -ConfirmWprCapture"
goto :run

:opt_basic
set "EXTRA="
goto :run

:opt_defender
set "EXTRA=-CaptureWpr -ConfirmWprCapture -CaptureDefender -ConfirmDefenderCapture"
goto :run

:opt_plan
echo Writing plan only...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Invoke-WindowsPerformanceDiagnostics.ps1" -Mode Plan -OutputDirectory "%OUTDIR%"
if errorlevel 1 (
    echo [ERROR] Plan mode failed. See %LOG%
    goto :end
)
echo Plan written to %OUTDIR%\diagnostic-plan.json
goto :end

:run
if not exist "%OUTDIR%" mkdir "%OUTDIR%"
echo.
echo Collecting for 30 seconds. Output: %OUTDIR%
echo Run started: %date% %time% - option %CHOICE% >> "%LOG%"
echo ============================================================ >> "%LOG%"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& '%~dp0src\Invoke-WindowsPerformanceDiagnostics.ps1' -Mode Collect -ConfirmLocalCollection %EXTRA% -DurationSeconds 30 -OutputDirectory '%OUTDIR%' 2>&1 | Tee-Object -FilePath '%LOG%'"
echo.
if not exist "%OUTDIR%\diagnostic-manifest.json" (
    echo [ERROR] Collection did not produce %OUTDIR%\diagnostic-manifest.json
    echo         See %LOG% for details.
    goto :end
)
echo Collection complete. Output saved to %OUTDIR%
echo   - diagnostic-manifest.json     (report + SHA-256 hashes)
echo   - performance-samples.csv      (CPU/memory/disk samples)
echo   - top-processes.json           (process snapshot)
echo   - system-events-last-24-hours.json
echo   - wpr-trace.etl                (only with options 1 or 3)
echo   - defender-performance.etl     (only with option 3)
echo Full log: %LOG%
echo.

:end
echo.
if not "%CI%"=="true" pause
popd
endlocal
