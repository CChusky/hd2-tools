@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" > nul 2>&1
cd /d "%~dp0"
cl /nologo /O2 /utf-8 /TP overlay.c /Fe:overlay.exe /link /SUBSYSTEM:WINDOWS gdiplus.lib user32.lib gdi32.lib
echo.
echo Build done. Errorlevel: %ERRORLEVEL%
