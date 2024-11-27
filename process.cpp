#include <iostream>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "iphlpapi.lib")

void displayProcessName(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess) {
        char processName[MAX_PATH];
        if (GetModuleFileNameExA(hProcess, nullptr, processName, sizeof(processName) / sizeof(char))) {
            std::cout << "Process Name: " << processName;
        }
        CloseHandle(hProcess);
    }
}

void listConnections() {
    PMIB_TCPTABLE_OWNER_PID pTcpTable;
    DWORD dwSize = 0;

    // First call will return buffer size
    GetExtendedTcpTable(nullptr, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    pTcpTable = (MIB_TCPTABLE_OWNER_PID *)malloc(dwSize);

    if (GetExtendedTcpTable(pTcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        std::cout << "TCP Connections:\n";
        for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID row = pTcpTable->table[i];

            std::cout << "Local Addr: " << (row.dwLocalAddr & 0xff) << "." 
                      << ((row.dwLocalAddr >> 8) & 0xff) << "." 
                      << ((row.dwLocalAddr >> 16) & 0xff) << "." 
                      << ((row.dwLocalAddr >> 24) & 0xff) 
                      << ":" << ntohs((u_short)row.dwLocalPort)
                      << " | Remote Addr: " << (row.dwRemoteAddr & 0xff) << "."
                      << ((row.dwRemoteAddr >> 8) & 0xff) << "." 
                      << ((row.dwRemoteAddr >> 16) & 0xff) << "." 
                      << ((row.dwRemoteAddr >> 24) & 0xff) 
                      << ":" << ntohs((u_short)row.dwRemotePort)
                      << " | PID: " << row.dwOwningPid << " | ";

            displayProcessName(row.dwOwningPid);
            std::cout << std::endl;
        }
    }
    free(pTcpTable);
}

int main() {
    listConnections();
    return 0;
}