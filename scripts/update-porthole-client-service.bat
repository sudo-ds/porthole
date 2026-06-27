@echo off
setlocal

set "REPO=%REPO%"
if "%REPO%"=="" set "REPO=sudo-ds/porthole"

set "SERVICE=%SERVICE%"
if "%SERVICE%"=="" set "SERVICE=porthole-client"

set "TARGET=%TARGET%"
if "%TARGET%"=="" set "TARGET=x86_64-pc-windows-msvc"

net session >nul 2>&1
if errorlevel 1 (
  echo Please run this script from an Administrator Command Prompt.
  exit /b 1
)

set "TMP=%TEMP%\porthole-update-%RANDOM%%RANDOM%"
mkdir "%TMP%" || exit /b 1
mkdir "%TMP%\extract" || exit /b 1

echo Fetching latest Porthole release from %REPO%...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop';" ^
  "$release = Invoke-RestMethod -Uri 'https://api.github.com/repos/%REPO%/releases/latest';" ^
  "$asset = $release.assets | Where-Object { $_.name -like ('*' + '%TARGET%' + '.zip') } | Select-Object -First 1;" ^
  "if (-not $asset) { throw 'No Windows release asset found for target %TARGET%' }" ^
  "$sha = $release.assets | Where-Object { $_.name -like ('*' + '%TARGET%' + '.zip.sha256') } | Select-Object -First 1;" ^
  "$asset.browser_download_url | Set-Content -Encoding ascii '%TMP%\asset-url.txt';" ^
  "if ($sha) { $sha.browser_download_url | Set-Content -Encoding ascii '%TMP%\sha-url.txt' }" ^
  "$release.tag_name | Set-Content -Encoding ascii '%TMP%\tag.txt'"
if errorlevel 1 goto fail

set /p TAG=<"%TMP%\tag.txt"
set /p ASSET_URL=<"%TMP%\asset-url.txt"
echo Downloading %TAG%...

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop';" ^
  "Invoke-WebRequest -Uri '%ASSET_URL%' -OutFile '%TMP%\porthole.zip'"
if errorlevel 1 goto fail

if exist "%TMP%\sha-url.txt" (
  set /p SHA_URL=<"%TMP%\sha-url.txt"
  echo Verifying SHA256...
  powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$ErrorActionPreference='Stop';" ^
    "Invoke-WebRequest -Uri '%SHA_URL%' -OutFile '%TMP%\porthole.zip.sha256';" ^
    "$expected = ((Get-Content -Raw '%TMP%\porthole.zip.sha256').Trim() -split '\s+')[0].ToLowerInvariant();" ^
    "$actual = (Get-FileHash -Algorithm SHA256 '%TMP%\porthole.zip').Hash.ToLowerInvariant();" ^
    "if ($expected -ne $actual) { throw ('SHA256 mismatch: expected ' + $expected + ', got ' + $actual) }"
  if errorlevel 1 goto fail
)

echo Extracting...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop';" ^
  "Expand-Archive -LiteralPath '%TMP%\porthole.zip' -DestinationPath '%TMP%\extract' -Force;" ^
  "$bin = Get-ChildItem -Path '%TMP%\extract' -Recurse -Filter porthole.exe | Select-Object -First 1;" ^
  "if (-not $bin) { throw 'Downloaded release did not contain porthole.exe' }" ^
  "$bin.FullName | Set-Content -Encoding ascii '%TMP%\new-bin.txt'"
if errorlevel 1 goto fail

set /p NEW_BIN=<"%TMP%\new-bin.txt"

if "%BIN_PATH%"=="" (
  powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$ErrorActionPreference='Stop';" ^
    "$svc = Get-CimInstance Win32_Service | Where-Object { $_.Name -eq '%SERVICE%' } | Select-Object -First 1;" ^
    "if (-not $svc) { throw 'Windows service %SERVICE% was not found' }" ^
    "$path = $svc.PathName.Trim();" ^
    "$quote = [char]34;" ^
    "if ($path.StartsWith($quote)) { $path = $path.Substring(1); $path = $path.Substring(0, $path.IndexOf($quote)) } else { $path = ($path -split '\s+', 2)[0] }" ^
    "$path | Set-Content -Encoding ascii '%TMP%\bin-path.txt'"
  if errorlevel 1 goto fail
  set /p BIN_PATH=<"%TMP%\bin-path.txt"
)

if not exist "%BIN_PATH%" (
  echo Installed binary not found: %BIN_PATH%
  goto fail
)

echo Stopping %SERVICE%...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop';" ^
  "$svc = Get-Service -Name '%SERVICE%';" ^
  "if ($svc.Status -ne 'Stopped') { Stop-Service -Name '%SERVICE%' -Force; $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) }"
if errorlevel 1 goto fail

echo Replacing %BIN_PATH%...
copy /Y "%BIN_PATH%" "%BIN_PATH%.bak" >nul
if errorlevel 1 goto restore

copy /Y "%NEW_BIN%" "%BIN_PATH%" >nul
if errorlevel 1 goto restore

echo Starting %SERVICE%...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop';" ^
  "Start-Service -Name '%SERVICE%';" ^
  "(Get-Service -Name '%SERVICE%').WaitForStatus('Running', [TimeSpan]::FromSeconds(30))"
if errorlevel 1 goto restore

echo.
echo Updated Porthole client service to %TAG%.
"%BIN_PATH%" --version
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-Service -Name '%SERVICE%' | Format-Table -AutoSize Name,Status"

rmdir /S /Q "%TMP%" >nul 2>&1
exit /b 0

:restore
echo Update failed after stopping the service. Restoring backup...
if exist "%BIN_PATH%.bak" copy /Y "%BIN_PATH%.bak" "%BIN_PATH%" >nul
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Service -Name '%SERVICE%'" >nul 2>&1
goto fail

:fail
echo.
echo Update failed.
echo Temp files left at: %TMP%
exit /b 1
