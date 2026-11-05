@echo off
rem Runs meson inside an MSVC x64 developer environment (located via vswhere).
setlocal
if defined VCINSTALLDIR goto run
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -all -prerelease -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR ( echo error: Visual Studio with C++ tools not found & exit /b 1 )
rem vcvars needs vswhere on PATH to locate the Windows SDK
set "PATH=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer;%PATH%"
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
:run
where meson >nul 2>nul || set "PATH=%APPDATA%\Python\Python314\Scripts;%PATH%"
meson %*
