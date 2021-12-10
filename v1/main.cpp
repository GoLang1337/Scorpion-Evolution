#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>

DWORD GetProcessIdByName(const char* processName)
{
    PROCESSENTRY32 processEntry; processEntry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(hProcess, &processEntry))
    {
        do
        {
            if (!lstrcmpi(processEntry.szExeFile, processName)) {
                CloseHandle(hProcess);
                return processEntry.th32ProcessID;
            }
        } while (Process32Next(hProcess, &processEntry));
    }

    return 0;
}

DWORD64 GetBaseAddress(const char* processName, DWORD pid)
{
    MODULEENTRY32 moduleEntry; moduleEntry.dwSize = sizeof(MODULEENTRY32);
    HANDLE hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

    if (Module32First(hProcess, &moduleEntry))
    {
        do
        {
            if (!lstrcmpi(moduleEntry.szModule, processName)) {
                CloseHandle(hProcess);
                return (DWORD64)moduleEntry.modBaseAddr;
            }
        } while (Module32Next(hProcess, &moduleEntry));
    }

    return 0;
}

int main()
{
    std::string processName;
    DWORD processId;

    printf("Insert process name: ");
    std::cin >> processName;

    do {
        processId = GetProcessIdByName(processName.c_str());
        printf("Waiting for the process...");
        Sleep(300);
        system("cls");
    } while (!processId);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

    if (hProcess == INVALID_HANDLE_VALUE) {
        printf("Error...");
        Sleep(5000);
        exit(0);
    }

    DWORD64 address = (GetBaseAddress(processName.c_str(), processId)) + 0x906E0;
    uint8_t patch[] = { 0xB0, 0x01, 0x84, 0xC0, 0xC3 };
    
    WriteProcessMemory(hProcess, (LPVOID)address, patch, sizeof(patch), NULL);
}
