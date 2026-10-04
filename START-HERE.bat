@echo off
setlocal
pushd "%~dp0"

set "OUTDIR=C:\WPD-Case"
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
echo   2 - Collect diagnostics + Search/minifilter snapshots (recommended)
echo   3 - Incident capture + Search/minifilter snapshots
echo   4 - Verify an existing case
echo   5 - Exit
echo.
set /p CHOICE="Enter 1-5: "

:choice_set
if "%CHOICE%"=="1" goto :opt_plan
if "%CHOICE%"=="2" goto :opt_collect
if "%CHOICE%"=="3" goto :opt_incident
if "%CHOICE%"=="4" goto :opt_verify
if "%CHOICE%"=="5" goto :exit_clean
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
set "LAUNCHMODE=GuidedCollect"
goto :run

:opt_incident
call :ensure_elevated
if "%errorlevel%"=="0" goto :incident_ready
if "%errorlevel%"=="1" goto :end_failed
goto :end_no_pause

:incident_ready
echo.
echo Incident capture runs ONE shared window for counters, process/commit,
echo GPU, disk, pagefile and the WPR trace. Press Enter when the slowdown
echo happens: 60 s before the marker and 30 s after it are kept.
echo Counters and the WPR trace are running in the SAME window.
set "LAUNCHMODE=IncidentCollect"
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
echo.
echo Collecting diagnostics. The console shows baseline progress by sample and percentage.
echo Allow additional time for event/log collection and final export, hashing, and ZIP packaging.
echo Read-only Search service and minifilter snapshots are included.
echo New case folders are created beneath %OUTDIR%.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Invoke-WpdLauncher.ps1" -LaunchMode "%LAUNCHMODE%"
if errorlevel 1 goto :collection_failed
echo.
echo Collection complete. The exact case directory, matching log, and manifest were verified above.
goto :end

:collection_failed
echo [ERROR] Collection failed or produced no manifest. Review the exact run path and log printed above.
goto :end_failed

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
