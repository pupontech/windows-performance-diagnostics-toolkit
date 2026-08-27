@echo off
setlocal
pushd "%~dp0"

echo ============================================
echo  Windows Performance Diagnostics Toolkit
echo  START HERE - full collection (admin)
echo ============================================
echo.
echo This will:
echo   - Collect CPU/memory/disk samples for 30s
echo   - Snapshot top processes and System events
echo   - Capture a 30-second WPR trace (needs admin)
echo.
echo Output: C:\Temp\WPD-Case
echo.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges (UAC)...
    powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo Running elevated collector with WPR capture...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Invoke-WindowsPerformanceDiagnostics.ps1" -Mode Collect -ConfirmLocalCollection -CaptureWpr -ConfirmWprCapture -DurationSeconds 30 -OutputDirectory "C:\Temp\WPD-Case"
echo.
echo Collection complete. Output saved to C:\Temp\WPD-Case
echo   - diagnostic-manifest.json   (report + SHA-256 hashes)
echo   - wpr-trace.etl              (WPR trace - open in WPA)
if not "%CI%"=="true" pause
popd
endlocal
