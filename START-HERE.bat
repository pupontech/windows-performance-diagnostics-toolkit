@echo off
setlocal
pushd "%~dp0"

set "OUTDIR=C:\Temp\WPD-Case"
set "LOG=%OUTDIR%\diagnostics-run.log"
set "CHOICE=%~1"
set "INPUTDIR=%~2"

title Windows Performance Diagnostics Toolkit - START HERE

echo ============================================================
echo  Windows Performance Diagnostics Toolkit - START HERE
echo ============================================================
echo.

REM ---- pre-flight: the collector must exist (Defender may strip downloaded .ps1) ----
if exist "%~dp0src\Invoke-WindowsPerformanceDiagnostics.ps1" goto :ps1_ok
echo [ERROR] src\Invoke-WindowsPerformanceDiagnostics.ps1 was not found.
echo.
echo Windows Security may have removed the downloaded script.
echo Recovery steps are in README-FIRST.txt:
echo   1. Right-click the zip in Explorer - Properties - check UNBLOCK - Extract
echo   2. If the .ps1 is gone after extraction, restore it from Windows Security
echo      Virus and threat protection - Protection history
echo   3. Then run:  powershell -Command "Unblock-File -Path '.\src\Invoke-WindowsPerformanceDiagnostics.ps1'"
goto :end

:ps1_ok
if not "%CHOICE%"=="" goto :choice_set
echo Choose an operating mode:
echo.
echo   1 - Plan preview
echo   2 - Collect diagnostics (recommended)
echo   3 - Verify an existing case
echo   4 - Exit
echo.
set /p CHOICE="Enter 1-4: "

:choice_set
if "%CHOICE%"=="1" goto :opt_plan
if "%CHOICE%"=="2" goto :opt_collect
if "%CHOICE%"=="3" goto :opt_verify
if "%CHOICE%"=="4" goto :exit_clean
echo [ERROR] Invalid choice: %CHOICE%
echo.
goto :end

:opt_plan
echo Writing plan only...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Invoke-WindowsPerformanceDiagnostics.ps1" -Mode Plan -OutputDirectory "%OUTDIR%"
if errorlevel 1 goto :plan_failed
echo Plan written to %OUTDIR%\diagnostic-plan.json
goto :end

:plan_failed
echo [ERROR] Plan mode failed.
goto :end_failed

:opt_collect
call :ensure_elevated
if "%errorlevel%"=="0" goto :collect_ready
if "%errorlevel%"=="1" goto :end_failed
goto :end_no_pause

:collect_ready
set "EXTRA=-CaptureWpr -ConfirmWprCapture -CollectMinidumps -ConfirmMinidumpCollection -CollectBootFailureLogs -ConfirmBootFailureLogCollection -ZipOutput"
goto :run

:opt_verify
if not defined INPUTDIR set /p INPUTDIR="Enter the case directory to verify: "
if not defined INPUTDIR goto :verify_failed
echo Verifying case: "%INPUTDIR%"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Invoke-WindowsPerformanceDiagnostics.ps1" -Mode Verify -InputDirectory "%INPUTDIR%"
if errorlevel 1 goto :verify_failed
echo Verify completed successfully.
goto :end

:verify_failed
echo [ERROR] Verify mode failed. Review the JSON report above.
goto :end_failed

:run
if not exist "%OUTDIR%" mkdir "%OUTDIR%"
echo.
echo Collecting for 30 seconds. Output: %OUTDIR%
echo Run started: %date% %time% - mode Collect >> "%LOG%"
echo ============================================================ >> "%LOG%"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& '%~dp0src\Invoke-WindowsPerformanceDiagnostics.ps1' -Mode Collect -ConfirmLocalCollection %EXTRA% -DurationSeconds 30 -OutputDirectory '%OUTDIR%' 2>&1 | Tee-Object -FilePath '%LOG%'"
echo.
if errorlevel 1 goto :collection_failed
if exist "%OUTDIR%\diagnostic-manifest.json" goto :manifest_ok
echo [ERROR] Collection did not produce %OUTDIR%\diagnostic-manifest.json
echo         See %LOG% for details.
goto :end_failed

:collection_failed
echo [ERROR] Collection returned a failure. See %LOG% for details.
goto :end_failed

:manifest_ok
echo Collection complete. Output saved to %OUTDIR%
echo   - diagnostic-manifest.json     (report + SHA-256 hashes)
echo   - performance-samples.csv      (CPU/memory/disk samples)
echo   - top-processes.json           (process snapshot)
echo   - system-events-last-24-hours.json
echo   - wpr-trace.etl                (when WPR is available)
echo   - minidumps\                   (crash dumps)
echo   - bootfailure\                 (SRT/boot/CBS logs)
echo   - WPD-Case-^<time^>.zip          (case package, next to the output folder)
echo Full log: %LOG%
echo.
goto :end

:ensure_elevated
net session >nul 2>&1
if %errorlevel% equ 0 exit /b 0
if "%CI%"=="true" goto :ci_not_elevated
echo Requesting administrator privileges via UAC...
echo.
powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%CHOICE%' -Verb RunAs"
exit /b 2

:ci_not_elevated
echo [ERROR] CI runner is not elevated; the elevated path cannot be tested here.
exit /b 1

:exit_clean
popd
endlocal
exit /b 0

:end_failed
echo.
if not "%CI%"=="true" pause
popd
endlocal
exit /b 1

:end_no_pause
popd
endlocal
exit /b 0

:end
echo.
if not "%CI%"=="true" pause
popd
endlocal
exit /b 0
