#pragma once
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "windivert.lib")

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
#define GET_NOW() time_point_cast<milliseconds>(system_clock::now()).time_since_epoch().count()

#include <chrono>
#include <set>
#include <sstream>
#include <valarray>
#include <map>
#include <vector>
#include <iostream>
#include <string>
#include <stdio.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <psapi.h>
#include <windivert.h>

using namespace std;
using namespace std::chrono;