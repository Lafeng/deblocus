@echo off
rem 
rem deblocus build script for windows.
rem 

set "project=%~dp0.."
call :Resolve %project% project
echo deblocus build script
echo working path: %project%
pushd %project%

set goExe=""
call :RunEx "where go",goExe 2> nul

if "%goExe%" == "" (
    echo Need golang/bin in env.PATH.
    goto Exit
)

if "%~1" == "clean" (
    echo go clean
    go clean
    goto Exit
)

set osext_path="%project%\src\bitbucket.org\kardianos\osext"

set hgExe=
call :RunEx "where hg",hgExe 2> nul
if "%hgExe%" == "" call :InstallOsext
if "%osext_err%" NEQ "0" goto Exit

set "GOPATH=%project%"
echo.
echo building (may download dependencies) ...

go get deblocus
if "%errorlevel%" == "0" (
    echo deblocus build done: %project%/bin
)
goto Exit

:InstallOsext

if exist %osext_path%\osext.go (
    set osext_err=0
    goto EOF
)

pushd %project%\script

if not exist osext.zip (
    set wget=
    set curl=
    call :RunEx "where wget",wget 2> nul
    call :RunEx "where curl",curl 2> nul

    if "%wget%" == "" if "%curl%" == "" (
        echo Need wget or curl in env.PATH.
        goto Exit
    )
    
    set osext_url="https://bitbucket.org/kardianos/osext/get/default.zip"
    if "%wget%" NEQ "" (
        %wget% -O osext.zip %osext_url%
    ) else (
        %curl% -o osext.zip %osext_url%
    )
)

mkdir %osext_path% 2> nul

set unzipExe=
call :RunEx "where unzip",unzipExe 2> nul

if "%unzipExe%" == "" (
    echo Need unzip in env.PATH.
    goto Exit
)
%unzipExe% -jo osext.zip -d %osext_path%

set osext_err=%errorlevel%
goto Exit

:RunEx
for /f "tokens=*" %%a in ('%~1') do set "%~2=%%a"
goto EOF

:Resolve
set %2=%~f1
goto EOF

:Exit
popd
goto EOF

:EOF