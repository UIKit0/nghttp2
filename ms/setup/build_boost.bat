@echo off

echo This script will build libs for the following configurations:
echo        x86 - Windows Phone / Windows Store - Debug / Release
echo        x64 - Windows Phone / Windows Store - Debug / Release
echo        arm - Windows Phone / Windows Store - Debug / Release
echo.
echo Note that currently, the script only builds the thread library and
echo any dependencies that thread requires.
echo.
echo This script assumes that you have followed the initial instructions
echo found at: 
echo    http://blogs.msdn.com/b/vcblog/archive/2014/07/18/using-boost-libraries-in-windows-store-and-phone-applications.aspx
echo Specifically, the Download and Setup Boost Sources section, not the 
echo Build section.
echo.
echo Additionally, it assumes that you have updated the version.hpp file
echo located in $BOOST_HOME\libs\config\include\boost to the appropriate 
echo version of Boost in the head repository.
echo.
echo Steven Gates' patches currently assume version 1.56 of boost.
echo.
echo To use this script run it from within the the base boost directory the 
echo checkout above was run from.
echo.
echo If you have not, press Ctrl-C to stop, otherwise return to continue.
pause

if NOT EXIST bin.v2 GOTO NOBINV2
@echo removing bin.v2
del /s /q bin.v2
rmdir /s /q bin.v2

:NOBINV2

@echo building x64 libs, store
cd libs\thread\build
b2 toolset=msvc-12.0 link=static link=shared windows-api=store architecture=x86 address-model=64 variant=release variant=debug
move ..\..\..\bin.v2\libs\thread\build\msvc-12.0\debug\address-model-64\architecture-x86 ..\..\..\bin.v2\libs\thread\build\msvc-12.0\debug\architecture-x64
rmdir /s /q ..\..\..\bin.v2\libs\thread\build\msvc-12.0\debug\address-model-64
move ..\..\..\bin.v2\libs\thread\build\msvc-12.0\release\address-model-64\architecture-x86 ..\..\..\bin.v2\libs\thread\build\msvc-12.0\release\architecture-x64
rmdir /s /q ..\..\..\bin.v2\libs\thread\build\msvc-12.0\release\address-model-64
move ..\..\..\bin.v2\libs\chrono\build\msvc-12.0\debug\address-model-64\architecture-x86 ..\..\..\bin.v2\libs\chrono\build\msvc-12.0\debug\architecture-x64
rmdir /s /q ..\..\..\bin.v2\libs\chrono\build\msvc-12.0\debug\address-model-64
move ..\..\..\bin.v2\libs\chrono\build\msvc-12.0\release\address-model-64\architecture-x86 ..\..\..\bin.v2\libs\chrono\build\msvc-12.0\release\architecture-x64
rmdir /s /q ..\..\..\bin.v2\libs\chrono\build\msvc-12.0\release\address-model-64
move ..\..\..\bin.v2\libs\system\build\msvc-12.0\debug\address-model-64\architecture-x86 ..\..\..\bin.v2\libs\system\build\msvc-12.0\debug\architecture-x64
rmdir /s /q ..\..\..\bin.v2\libs\system\build\msvc-12.0\debug\address-model-64
move ..\..\..\bin.v2\libs\system\build\msvc-12.0\release\address-model-64\architecture-x86 ..\..\..\bin.v2\libs\system\build\msvc-12.0\release\architecture-x64
rmdir /s /q ..\..\..\bin.v2\libs\system\build\msvc-12.0\release\address-model-64

@echo building x86 and arm libs, phone and store
b2 toolset=msvc-12.0 link=static link=shared windows-api=store windows-api=phone architecture=x86 architecture=arm variant=release variant=debug

cd ..\..\..
@echo done