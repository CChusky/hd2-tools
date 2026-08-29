@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" > nul 2>&1
cd /d "c:\Users\Administrator\.trae-cn\work\6a856504b9374ddbb7e8706b"
cl /O2 /W0 watcher.c /link /OUT:watcher.exe psapi.lib user32.lib
echo Build done. Errorlevel: %ERRORLEVEL%
