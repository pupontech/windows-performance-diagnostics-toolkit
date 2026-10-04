@echo off
setlocal
set "OUTDIR=C:\WPD-Case"
if not defined WPD_POWERSHELL_EXE set "WPD_POWERSHELL_EXE=powershell.exe"
pushd "%~dp0"
echo.
echo ============================================
echo  Windows Performance Diagnostics Collector
echo ============================================
echo.
echo This run performs 30-second baseline sampling.
echo Read-only Search service and minifilter snapshots are included.
echo Allow additional time for crash-evidence copies and final export, hashing, and ZIP packaging.
echo The collector prints live baseline sample and percentage progress.
echo New case folders are created beneath %OUTDIR%.
"%WPD_POWERSHELL_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Invoke-WpdLauncher.ps1" -LaunchMode StandaloneCollect
if errorlevel 1 goto :collection_failed
echo.
echo Diagnostics collection complete. The exact case directory, matching log, and manifest were verified above.
if not "%CI%"=="true" pause
popd
endlocal & exit /b 0

:collection_failed
echo.
echo [ERROR] Diagnostics collection failed or produced no manifest.
echo Review the exact run path and log printed above.
if not "%CI%"=="true" pause
popd
endlocal & exit /b 1
