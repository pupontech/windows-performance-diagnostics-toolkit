@echo off
pushd "%~dp0"
echo.
echo ============================================
echo  Windows Performance Diagnostics Collector
echo ============================================
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Invoke-WindowsPerformanceDiagnostics.ps1" -Mode Collect -ConfirmLocalCollection -DurationSeconds 30 -OutputDirectory "C:\Temp\WPD-Case\"
echo.
echo Diagnostics collection complete. Output saved to C:\Temp\WPD-Case\
pause
popd
