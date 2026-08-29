@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" > nul 2>&1
cd /d "C:\Users\Administrator\AppData\Roaming\TRAE SOLO CN\ModularData\ai-agent\work-mode-projects\6a856504b9374ddbb7e87068"
rc /fo watcher.res watcher.rc
cl /nologo /O2 /W0 /utf-8 watcher.c watcher.res /link /OUT:watcher.exe psapi.lib user32.lib advapi32.lib
echo.
echo Build done. Errorlevel: %ERRORLEVEL%
