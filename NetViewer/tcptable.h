#pragma once
#include "headers.h"


class Tabler {
private:
    PMIB_TCPTABLE2 pTcpTable;
    ULONG ulTcpTableSize;
    DWORD dwgetTableRv;
public:
    Tabler();
    void initTcpTable();
    string queryProcessNameByFlow(UINT32 localAddr, UINT32 remoteAddr, UINT16 nLocalPort, UINT16 nRemotePort);
    void printTable();
    string formatIP(UINT32 ip);
    string getProcessName(UINT32 pid);
};