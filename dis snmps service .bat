@echo off
REM Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c %~s0' -Verb RunAs"
    exit /b
)

echo Disabling SNMP and SNMP Trap Services...

rem Stop and disable the main SNMP Service
net stop snmp >nul 2>&1
sc config snmp start= disabled >nul 2>&1

rem Stop and disable the SNMP Trap Service
net stop "SNMP Trap" >nul 2>&1
sc config "SNMP Trap" start= disabled >nul 2>&1

echo Operation completed successfully.
pause