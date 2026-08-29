@echo off
rem Pure data build (no ReShade addon): hook writes shm only, display via external overlay.exe
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" > nul 2>&1
cd /d "C:\Users\Administrator\AppData\Roaming\TRAE SOLO CN\ModularData\ai-agent\work-mode-projects\6a856504b9374ddbb7e87068"
cl /LD /O2 /W0 /EHsc /std:c++17 /utf-8 hd2_raycast_hook.c hd2_addon_stub.c /link /OUT:hd2_raycast_hook_clean.dll user32.lib gdi32.lib
echo.
echo Clean build done. Errorlevel: %ERRORLEVEL%
