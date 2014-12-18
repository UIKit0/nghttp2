#include "pch.h"
#include "WinRTCClass.h"
#include "asio-client.h"
using namespace WinRTC;
using namespace Platform;

WinRTCClass::WinRTCClass()
{
}

int WinRTCClass::InvokeTest()
{
    //OutputDebugString(L"Vivek test");
    runWithUri("https://nghttp2.org/");

    static int i = 0;
    return i++;
}