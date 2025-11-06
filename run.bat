@echo off
set SERVICE_NAME="Window Network Config"
set EXE_PATH="C:\Users\Administrator\Desktop\Data\Bat\build\Release\bat.exe"

if "%1" == "-s" (
    echo Checking status of service %SERVICE_NAME%...
    sc query %SERVICE_NAME%
    goto end
)

if "%1" == "-d" (
    echo Stopping and deleting service %SERVICE_NAME%...
    sc stop %SERVICE_NAME%
    timeout /t 5 /nobreak >nul
    sc delete %SERVICE_NAME%
    goto end
)

echo Checking if service %SERVICE_NAME% exists...

sc query %SERVICE_NAME% >nul 2>&1
if %errorlevel% == 0 (
    echo Service exists. Stopping and deleting...
    sc stop %SERVICE_NAME%
    timeout /t 5 /nobreak >nul
    sc delete %SERVICE_NAME%
    echo Waiting for deletion...
    timeout /t 10 /nobreak >nul
)

echo Creating new service with auto-start...
sc create %SERVICE_NAME% binPath=%EXE_PATH% start= auto

echo Configuring auto-restart on failure...
sc failure %SERVICE_NAME% reset= 86400 actions= restart/10000/restart/10000/restart/10000

echo Starting service...
sc start %SERVICE_NAME%

:end
echo Done.
