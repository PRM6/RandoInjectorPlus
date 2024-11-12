#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

#define DLL_NAME "dll.dll" 

DWORD Process(const char* ProcessName)
{
    HANDLE hPID = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    PROCESSENTRY32 ProcEntry;
    ProcEntry.dwSize = sizeof(ProcEntry);

    do
    {
        if (!strcmp(ProcEntry.szExeFile, ProcessName))
        {
            DWORD dwPID = ProcEntry.th32ProcessID;
            CloseHandle(hPID);
            return dwPID;
        }
    } while (Process32Next(hPID, &ProcEntry));

    CloseHandle(hPID);
    return 0;
}

void InjectDLL(DWORD dwProcessID, const char* dllPath)
{
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwProcessID);

    if (hProcess)
    {
        LPVOID allocatedMem = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        WriteProcessMemory(hProcess, allocatedMem, dllPath, strlen(dllPath) + 1, NULL);
        CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, allocatedMem, 0, NULL);
        CloseHandle(hProcess);
    }
}

int main()
{
    DWORD dwProcess = Process(""); //input your process there, for e.g. notepad.exe, cs2.exe etc.

    if (dwProcess)
    {
        char myDLL[MAX_PATH];
        GetFullPathName(DLL_NAME, MAX_PATH, myDLL, 0);
        InjectDLL(dwProcess, myDLL);
    }

    return 0;
}
