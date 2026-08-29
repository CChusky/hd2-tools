@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" > nul 2>&1
cd /d "c:\Users\Administrator\.trae-cn\work\6a856504b9374ddbb7e8706b\hd2_addon"
cl /LD /O2 /W3 /EHsc /std:c++17 /I. /Ireshade_src\include main.cpp /link /OUT:hd2_addon.addon64
echo.
echo Addon build done. Errorlevel: %ERRORLEVEL%
