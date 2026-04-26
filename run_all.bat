@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

:: ============================================================
::  WAF Test Runner - run_all.bat
::  Usage: run_all.bat [all|pytest|k6|sqlmap]
::  Default: all
::
::  Results structure:
::    tests_result\pytest\<TIMESTAMP>\
::    tests_result\k6\<TIMESTAMP>\
::    tests_result\sqlmap\<TIMESTAMP>\
:: ============================================================

:: -- Parse argument ------------------------------------------
set "ARG=%~1"
if /i "%ARG%"=="" set "ARG=all"

if /i "%ARG%"=="all"    goto :arg_ok
if /i "%ARG%"=="pytest" goto :arg_ok
if /i "%ARG%"=="k6"     goto :arg_ok
if /i "%ARG%"=="sqlmap" goto :arg_ok

echo.
echo [ERROR] Invalid argument: "%ARG%"
echo Usage: run_all.bat [all^|pytest^|k6^|sqlmap]
echo.
exit /b 2

:arg_ok

:: -- Config --------------------------------------------------
set WAF_URL=https://localhost
set DIRECT_URL=http://localhost:5001

set PYTEST_DIR=%~dp0tests\security\pytest
set K6_DIR=%~dp0tests\performance\k6
set RESULT_BASE=%~dp0tests_result

:: Locale-safe timestamp via PowerShell
for /f %%I in ('powershell -noprofile -command "Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'"') do set TS=%%I

:: Per-tool result dirs
set PYTEST_RUN=%RESULT_BASE%\pytest\%TS%
set K6_RUN=%RESULT_BASE%\k6\%TS%
set SQLMAP_RUN=%RESULT_BASE%\sqlmap\%TS%

echo.
echo ======================================================
echo    WAF Full Test Suite - run_all.bat
echo ======================================================
echo   Mode    : %ARG%
echo   WAF URL : %WAF_URL%
echo   Started : %DATE% %TIME%
echo.

:: -- Decide which blocks to run ------------------------------
set RUN_PYTEST=0
set RUN_K6=0
set RUN_SQLMAP=0

if /i "%ARG%"=="all" (
    set RUN_PYTEST=1
    set RUN_K6=1
    set RUN_SQLMAP=1
)
if /i "%ARG%"=="pytest" set RUN_PYTEST=1
if /i "%ARG%"=="k6"     set RUN_K6=1
if /i "%ARG%"=="sqlmap" set RUN_SQLMAP=1

set PASS=0
set FAIL=0
set SKIP=0

:: ============================================================
::  BLOCK 1 - pytest
:: ============================================================
if %RUN_PYTEST%==0 goto :k6_block

echo ----------------------------------------------------------
echo   [1] pytest - Security Unit Tests
echo   Output: %PYTEST_RUN%
echo ----------------------------------------------------------

python -m pytest --version >nul 2>&1
if errorlevel 1 (
    echo   [SKIP] pytest / python not found
    set /a SKIP+=1
    goto :k6_block
) else (
    set PYTEST_CMD=python -m pytest
)

mkdir "%PYTEST_RUN%" 2>nul

set HTML_ARGS=
python -c "import pytest_html" >nul 2>&1
if not errorlevel 1 (
    set HTML_ARGS=--html="%PYTEST_RUN%\report.html" --self-contained-html
)

set WAF_BASE=%WAF_URL%
set DIRECT_BASE=%DIRECT_URL%

echo   Running pytest...
%PYTEST_CMD% "%PYTEST_DIR%" ^
    --tb=short -v ^
    --junit-xml="%PYTEST_RUN%\junit.xml" ^
    %HTML_ARGS% ^
    > "%PYTEST_RUN%\pytest.log" 2>&1

if errorlevel 1 (
    echo   [FAIL] Some pytest tests failed
    set /a FAIL+=1
) else (
    echo   [PASS] All pytest tests passed
    set /a PASS+=1
)
echo   Results: %PYTEST_RUN%

:: ============================================================
::  BLOCK 2 - k6
:: ============================================================
:k6_block
if %RUN_K6%==0 goto :sqlmap_block

echo.
echo ----------------------------------------------------------
echo   [2] k6 - Baseline and Stress Test
echo   Output: %K6_RUN%
echo ----------------------------------------------------------

where k6 >nul 2>&1
if errorlevel 1 (
    echo   [SKIP] k6 not found - install from https://k6.io/docs/get-started/installation/
    set /a SKIP+=1
    goto :sqlmap_block
)
for /f "tokens=*" %%V in ('k6 version 2^>^&1') do echo   Found: %%V

mkdir "%K6_RUN%" 2>nul

echo   Running baseline test...
k6 run --env WAF_URL=%WAF_URL% ^
    --out "json=%K6_RUN%\baseline_raw.json" ^
    "%K6_DIR%\baseline.js" ^
    > "%K6_RUN%\baseline.log" 2>&1
set K6_BASELINE_EXIT=%errorlevel%
type "%K6_RUN%\baseline.log"

if %K6_BASELINE_EXIT% neq 0 (
    echo   [FAIL] k6 baseline failed
    set /a FAIL+=1
) else (
    echo   [PASS] k6 baseline passed
    set /a PASS+=1
)

echo.
echo   Waiting 5 seconds before stress test...
timeout /t 5 /nobreak >nul

echo   Running stress test...
k6 run --env WAF_URL=%WAF_URL% ^
    --out "json=%K6_RUN%\stress_raw.json" ^
    "%K6_DIR%\stress.js" ^
    > "%K6_RUN%\stress.log" 2>&1
set K6_STRESS_EXIT=%errorlevel%
type "%K6_RUN%\stress.log"

if %K6_STRESS_EXIT% neq 0 (
    echo   [FAIL] k6 stress failed threshold
    set /a FAIL+=1
) else (
    echo   [PASS] k6 stress passed
    set /a PASS+=1
)

echo.
echo   Results: %K6_RUN%
echo   (see baseline.log / stress.log for full output)

:: ============================================================
::  BLOCK 3 - sqlmap
:: ============================================================
:sqlmap_block
if %RUN_SQLMAP%==0 goto :summary

echo.
echo ----------------------------------------------------------
echo   [3] sqlmap - SQLi Penetration Test
echo   Output: %SQLMAP_RUN%
echo ----------------------------------------------------------

set SQLMAP_CMD=
where sqlmap >nul 2>&1
if not errorlevel 1 (
    set SQLMAP_CMD=sqlmap
    goto :sqlmap_found
)
if exist "%~dp0sqlmap\sqlmap.py" (
    set SQLMAP_CMD=python "%~dp0sqlmap\sqlmap.py"
    goto :sqlmap_found
)
if exist "%~dp0sqlmap.py" (
    set SQLMAP_CMD=python "%~dp0sqlmap.py"
    goto :sqlmap_found
)
for /f "delims=" %%P in ('python -c "import sqlmap,os; print(os.path.join(os.path.dirname(sqlmap.__file__),'sqlmap.py'))" 2^>nul') do (
    if exist "%%P" (
        set SQLMAP_CMD=python "%%P"
        goto :sqlmap_found
    )
)
echo   [SKIP] sqlmap not found
echo          Option 1: pip install sqlmap
echo          Option 2: git clone https://github.com/sqlmapproject/sqlmap
set /a SKIP+=1
goto :summary

:sqlmap_found
set BASE_FLAGS=--batch --level=5 --risk=3 --technique=BEUST --random-agent --timeout=15 --retries=2 --ignore-code=403,429
set "POST_DATA=username=admin&password=test"

mkdir "%SQLMAP_RUN%" 2>nul

echo   [01] WAF GET /search
%SQLMAP_CMD% -u "%WAF_URL%/search?q=test" %BASE_FLAGS% --no-cast ^
    --output-dir="%SQLMAP_RUN%\01_waf_search_get" ^
    > "%SQLMAP_RUN%\01_waf_search_get.log" 2>&1
call :sqlmap_result "%SQLMAP_RUN%\01_waf_search_get.log"

echo   [02] WAF POST /login
%SQLMAP_CMD% -u "%WAF_URL%/login" --data="%POST_DATA%" %BASE_FLAGS% ^
    --output-dir="%SQLMAP_RUN%\02_waf_login_post" ^
    > "%SQLMAP_RUN%\02_waf_login_post.log" 2>&1
call :sqlmap_result "%SQLMAP_RUN%\02_waf_login_post.log"

echo   [03] Direct backend (no WAF) - Expected VULNERABLE (baseline)
%SQLMAP_CMD% -u "%DIRECT_URL%/search?q=test" %BASE_FLAGS% --no-cast ^
    --output-dir="%SQLMAP_RUN%\03_direct_bypass" ^
    > "%SQLMAP_RUN%\03_direct_bypass.log" 2>&1
findstr /i "is vulnerable\|appears to be\|sqlmap identified" "%SQLMAP_RUN%\03_direct_bypass.log" >nul 2>&1
if not errorlevel 1 (
    echo        ^ VULNERABLE detected (expected - no WAF protection)
) else (
    echo        No injection found
)

echo   [04] Tamper: space2comment,randomcase
%SQLMAP_CMD% -u "%WAF_URL%/search?q=test" %BASE_FLAGS% --tamper=space2comment,randomcase ^
    --output-dir="%SQLMAP_RUN%\04_tamper_space2comment" ^
    > "%SQLMAP_RUN%\04_tamper_space2comment.log" 2>&1
call :sqlmap_result "%SQLMAP_RUN%\04_tamper_space2comment.log"

echo   [05] Tamper: charencode,between
%SQLMAP_CMD% -u "%WAF_URL%/search?q=test" %BASE_FLAGS% --tamper=charencode,between ^
    --output-dir="%SQLMAP_RUN%\05_tamper_charencode" ^
    > "%SQLMAP_RUN%\05_tamper_charencode.log" 2>&1
call :sqlmap_result "%SQLMAP_RUN%\05_tamper_charencode.log"

echo   [06] Tamper: base64encode
%SQLMAP_CMD% -u "%WAF_URL%/search?q=test" %BASE_FLAGS% --tamper=base64encode ^
    --output-dir="%SQLMAP_RUN%\06_tamper_base64" ^
    > "%SQLMAP_RUN%\06_tamper_base64.log" 2>&1
call :sqlmap_result "%SQLMAP_RUN%\06_tamper_base64.log"

echo   [07] Tamper: charunicodeescape,randomcase
%SQLMAP_CMD% -u "%WAF_URL%/search?q=test" %BASE_FLAGS% --tamper=charunicodeescape,randomcase ^
    --output-dir="%SQLMAP_RUN%\07_tamper_unicode" ^
    > "%SQLMAP_RUN%\07_tamper_unicode.log" 2>&1
call :sqlmap_result "%SQLMAP_RUN%\07_tamper_unicode.log"

echo   [08] POST double URL-encode
%SQLMAP_CMD% -u "%WAF_URL%/login" --data="%POST_DATA%" %BASE_FLAGS% --tamper=chardoubleencode ^
    --output-dir="%SQLMAP_RUN%\08_tamper_doubleencode_post" ^
    > "%SQLMAP_RUN%\08_tamper_doubleencode_post.log" 2>&1
call :sqlmap_result "%SQLMAP_RUN%\08_tamper_doubleencode_post.log"

echo.
set SQLI_VULN=0
for %%f in ("%SQLMAP_RUN%\*.log") do (
    :: Skip 03_direct_bypass.log - backend has no WAF, expected VULNERABLE
    echo "%%f" | findstr /i "03_direct_bypass" >nul 2>&1
    if errorlevel 1 (
        findstr /i "is vulnerable\|appears to be\|sqlmap identified" "%%f" >nul 2>&1
        if not errorlevel 1 set SQLI_VULN=1
    )
)
if !SQLI_VULN!==1 (
    echo   [FAIL] sqlmap found SQLi - WAF blocking insufficient
    set /a FAIL+=1
) else (
    echo   [PASS] sqlmap found no SQLi vulnerability
    set /a PASS+=1
)
echo   Results: %SQLMAP_RUN%

:: ============================================================
::  SUMMARY
:: ============================================================
:summary
echo.
echo ======================================================
echo                     FINAL SUMMARY
echo ======================================================
echo   Mode : %ARG%
echo   PASS : %PASS%
echo   FAIL : %FAIL%
echo   SKIP : %SKIP%
echo.
if %RUN_PYTEST%==1 echo   pytest  : %PYTEST_RUN%
if %RUN_K6%==1     echo   k6      : %K6_RUN%
if %RUN_SQLMAP%==1 echo   sqlmap  : %SQLMAP_RUN%
echo.
if %FAIL% GTR 0 (
    echo   [!] Some tests failed - check log files for details
    echo.
    exit /b 1
) else (
    echo   [OK] All tests passed
    echo.
    exit /b 0
)

:: ============================================================
::  Subroutine: check sqlmap log for result
:: ============================================================
:sqlmap_result
findstr /i "is vulnerable\|appears to be\|sqlmap identified" "%~1" >nul 2>&1
if not errorlevel 1 (
    echo        ^ VULNERABLE detected
) else (
    findstr /i "no injection" "%~1" >nul 2>&1
    if not errorlevel 1 (
        echo        No injection found
    ) else (
        echo        (check log for details)
    )
)
goto :eof