#include "pch.h"
#include "WinRTCClass.h"

using namespace WinRTC;
using namespace Platform;

WinRTCClass::WinRTCClass()
{
}

int WinRTCClass::InvokeTest()
{
    static int i = 0;
    return i++;
}