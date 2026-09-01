@echo off
setlocal
set "OUTDIR=C:\Temp\WPD-Case"
pushd "%~dp0"
echo.
echo ============================================
echo  Windows Performance Diagnostics Collector
echo ============================================
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Invoke-WindowsPerformanceDiagnostics.ps1" -Mode Collect -ConfirmLocalCollection -CollectMinidumps -ConfirmMinidumpCollection -CollectBootFailureLogs -ConfirmBootFailureLogCollection -ZipOutput -DurationSeconds 30 -OutputDirectory "%OUTDIR%"
if errorlevel 1 goto :collection_failed
if not exist "%OUTDIR%\diagnostic-manifest.json" goto :collection_failed
echo.
echo Diagnostics collection complete. Output saved to %OUTDIR%
if not "%CI%"=="true" pause
popd
endlocal & exit /b 0

:collection_failed
echo.
echo [ERROR] Diagnostics collection failed or produced no manifest.
echo Review the console output and any files in %OUTDIR% for details.
if not "%CI%"=="true" pause
popd
endlocal & exit /b 1
