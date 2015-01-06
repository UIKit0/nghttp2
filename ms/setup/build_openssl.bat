@echo off

echo This batch file will build OpenSSL for Windows Phone / Windows Store
echo applications.  It assumes that you have already retrieved a version
echo of OpenSSL from:
echo    https://github.com/Microsoft/openssl
echo into a directory.
echo.
echo It also assumes that you have installed prerequisites (like Perl)
echo according to the INSTALL.WINAPP file.
echo.
echo You need to run this script from directory you cloned the above 
echo repository into and specify the directory you wish the OpenSSL 
echo libraries be installed into.
echo.
echo The script will create the following directory structure in the
echo specified directory:
echo.
echo    bin\
echo    lib\
echo    include\
echo.
echo Press Control-C to stop or Enter to continue.
pause

if "%1" == "" goto USAGE
if not exist "%1" goto NODIR

del /s /q vsout
rmdir /s /q vsout

echo Creating solution file
call ms\do_vsprojects.bat

echo Building libs
cd vsout
msbuild NT-Store-8.1-Dll-Unicode\NT-Store-8.1-Dll-Unicode.vcxproj /p:Configuration="Release" /p:Platform="x86" /verbosity:minimal
msbuild NT-Store-8.1-Dll-Unicode\NT-Store-8.1-Dll-Unicode.vcxproj /p:Configuration="Debug" /p:Platform="x86" /verbosity:minimal
msbuild NT-Store-8.1-Dll-Unicode\NT-Store-8.1-Dll-Unicode.vcxproj /p:Configuration="Release" /p:Platform="x64" /verbosity:minimal
msbuild NT-Store-8.1-Dll-Unicode\NT-Store-8.1-Dll-Unicode.vcxproj /p:Configuration="Debug" /p:Platform="x64" /verbosity:minimal
msbuild NT-Store-8.1-Dll-Unicode\NT-Store-8.1-Dll-Unicode.vcxproj /p:Configuration="Release" /p:Platform="arm" /verbosity:minimal
msbuild NT-Store-8.1-Dll-Unicode\NT-Store-8.1-Dll-Unicode.vcxproj /p:Configuration="Debug" /p:Platform="arm" /verbosity:minimal
msbuild NT-Store-8.1-Static-Unicode\NT-Store-8.1-Static-Unicode.vcxproj /p:Configuration="Release" /p:Platform="x86" /verbosity:minimal
msbuild NT-Store-8.1-Static-Unicode\NT-Store-8.1-Static-Unicode.vcxproj /p:Configuration="Debug" /p:Platform="x86" /verbosity:minimal
msbuild NT-Store-8.1-Static-Unicode\NT-Store-8.1-Static-Unicode.vcxproj /p:Configuration="Release" /p:Platform="x64" /verbosity:minimal
msbuild NT-Store-8.1-Static-Unicode\NT-Store-8.1-Static-Unicode.vcxproj /p:Configuration="Debug" /p:Platform="x64" /verbosity:minimal
msbuild NT-Store-8.1-Static-Unicode\NT-Store-8.1-Static-Unicode.vcxproj /p:Configuration="Release" /p:Platform="arm" /verbosity:minimal
msbuild NT-Store-8.1-Static-Unicode\NT-Store-8.1-Static-Unicode.vcxproj /p:Configuration="Debug" /p:Platform="arm" /verbosity:minimal
msbuild NT-Phone-8.1-Dll-Unicode\NT-Phone-8.1-Dll-Unicode.vcxproj /p:Configuration="Release" /p:Platform="x86" /verbosity:minimal
msbuild NT-Phone-8.1-Dll-Unicode\NT-Phone-8.1-Dll-Unicode.vcxproj /p:Configuration="Debug" /p:Platform="x86" /verbosity:minimal
msbuild NT-Phone-8.1-Dll-Unicode\NT-Phone-8.1-Dll-Unicode.vcxproj /p:Configuration="Release" /p:Platform="arm" /verbosity:minimal
msbuild NT-Phone-8.1-Dll-Unicode\NT-Phone-8.1-Dll-Unicode.vcxproj /p:Configuration="Debug" /p:Platform="arm" /verbosity:minimal
msbuild NT-Phone-8.1-Static-Unicode\NT-Phone-8.1-Static-Unicode.vcxproj /p:Configuration="Release" /p:Platform="x86" /verbosity:minimal
msbuild NT-Phone-8.1-Static-Unicode\NT-Phone-8.1-Static-Unicode.vcxproj /p:Configuration="Debug" /p:Platform="x86" /verbosity:minimal
msbuild NT-Phone-8.1-Static-Unicode\NT-Phone-8.1-Static-Unicode.vcxproj /p:Configuration="Release" /p:Platform="arm" /verbosity:minimal
msbuild NT-Phone-8.1-Static-Unicode\NT-Phone-8.1-Static-Unicode.vcxproj /p:Configuration="Debug" /p:Platform="arm" /verbosity:minimal
cd ..

echo Packaging openssl
call ms\do_packwinapp.bat

echo Copying openssl to destination
xcopy /e vsout\package\* %1\

goto END

:NODIR
echo "%1" Does not exist.
echo.

:USAGE
echo Command usage:
echo "%0 <destination dir>"

:END