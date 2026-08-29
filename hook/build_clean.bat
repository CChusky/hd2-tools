@echo off
rem Public build (F4 + Numpad1 only, pure data, no ReShade addon):
rem hook writes shared memory only; display via external overlay.exe
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" > nul 2>&1
cd /d "%~dp0"
cl /LD /O2 /W3 /EHsc /std:c++17 /utf-8 hd2_raycast_hook.c hd2_addon_stub.c /link /OUT:hd2_raycast_hook.dll user32.lib gdi32.lib
echo.
echo Build done. Errorlevel: %ERRORLEVEL%
