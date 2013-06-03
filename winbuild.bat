@echo off

for /F "tokens=1,2*" %%i in ('reg query "HKLM\Software\Wow6432Node\Microsoft\VisualStudio\SxS\VC7"') DO (
   if "%%i"=="10.0" SET "FOUND_DIR=%%k"
   if "%%i"=="11.0" SET "FOUND_DIR=%%k"
)

if "%FOUND_DIR%" == "" (
  echo Visual Studio Not Found >&2
  set RC=255
  goto ll_done
)

call "%FOUND_DIR%\bin\vcvars32.bat"
"%FOUND_DIR%\bin\cl.exe" %*
set RC=%ERRORLEVEL%

:ll_done
set ERRORLEVEL=%RC%

