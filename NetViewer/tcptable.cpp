#include "headers.h"
#include "tcptable.h"

// ref https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-gettcptable2

Tabler::Tabler() {
    pTcpTable = NULL;
    ulTcpTableSize = 0;
    dwgetTableRv = 0;
}

void Tabler::initTcpTable() {
    pTcpTable = (MIB_TCPTABLE2*)MALLOC(sizeof(MIB_TCPTABLE2));
    if (pTcpTable == NULL) {
        printf("Error allocating memory\n");
        exit(1);
    }
    ulTcpTableSize = sizeof(MIB_TCPTABLE);
    if ((dwgetTableRv = GetTcpTable2(pTcpTable, &ulTcpTableSize, TRUE)) == ERROR_INSUFFICIENT_BUFFER) {
        FREE(pTcpTable);
        pTcpTable = (MIB_TCPTABLE2*)MALLOC(ulTcpTableSize);
        if (pTcpTable == NULL) {
            printf("Error allocating memory\n");
            exit(1);
        }
    }
    // TODO: 之后仍然有可能 ERROR_INSUFFICIENT_BUFFER，可能需要进行动态的init
}

void Tabler::printTable() {
    if ((dwgetTableRv = GetTcpTable2(pTcpTable, &ulTcpTableSize, TRUE)) == NO_ERROR) {
        for (int i = 0; i < (int)pTcpTable->dwNumEntries; i++) {
            printf("[p:%d][flow:%d] %s:%d -> %s:%d\n", pTcpTable->table[i].dwOwningPid, i,
                formatIP(pTcpTable->table[i].dwLocalAddr).c_str(), ntohs((u_short)pTcpTable->table[i].dwLocalPort),
                formatIP(pTcpTable->table[i].dwRemoteAddr).c_str(), ntohs((u_short)pTcpTable->table[i].dwRemotePort)
            );
        }
    }
    else {
        printf("GetTcpTable2 failed with %d\n", dwgetTableRv);
    }
}

string Tabler::queryProcessNameByFlow(UINT32 localAddr, UINT32 remoteAddr, UINT16 nLocalPort, UINT16 nRemotePort) {
    if ((dwgetTableRv = GetTcpTable2(pTcpTable, &ulTcpTableSize, TRUE)) == NO_ERROR) {
        for (int i = 0; i < (int)pTcpTable->dwNumEntries; i++) {
            if (
                pTcpTable->table[i].dwLocalAddr == localAddr &&
                pTcpTable->table[i].dwRemoteAddr == remoteAddr &&
                pTcpTable->table[i].dwLocalPort == nLocalPort &&
                pTcpTable->table[i].dwRemotePort == nRemotePort
                )
            {
                return getProcessName(pTcpTable->table[i].dwOwningPid);
            }
        }
    }
    else {
        return "<GetTableErr>";
    }

    return "<unknown>";
}


string Tabler::formatIP(UINT32 ip) {
    struct in_addr IpAddr{};
    IpAddr.S_un.S_addr = (u_long)ip;
    string rv(inet_ntoa(IpAddr));
    return rv;
}

string Tabler::getProcessName(UINT32 pid) {
    if (pid == 0)
    {
        return "SYSTEM";
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    char processName[MAX_PATH]{};
    if (NULL != hProcess)
    {
        HMODULE hMod;
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
        {
            GetModuleBaseNameA(hProcess, hMod, processName, sizeof(processName) / sizeof(TCHAR));
        }
        CloseHandle(hProcess);
    }
    else {
       // Known PID but process gone or cannot retrieve it
       return std::to_string(pid);
    }

    string rv(processName);
    return rv;
}