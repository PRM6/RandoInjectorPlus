#include <Windows.h>
#include <TlHelp32.h>
#include <commdlg.h>
#include <string>
#include <iostream>

bool SelectDLL(std::string& dllPath) {
    char fileBuffer[MAX_PATH] = { 0 };
    OPENFILENAME ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = fileBuffer;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = "DLL files\0*.dll\0All files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrTitle = "Select DLL for Injection";
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileName(&ofn)) {
        dllPath = fileBuffer;
        return true;
    }
    return false;
}

DWORD FindProcessID(const std::string& processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        MessageBox(NULL, "Failed to create snapshot of running processes.", "Error", MB_ICONERROR);
        return 0;
    }

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    DWORD processID = 0;
    if (Process32First(snapshot, &processEntry)) {
        do {
            if (_stricmp(processEntry.szExeFile, processName.c_str()) == 0) {
                processID = processEntry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &processEntry));
    }
    CloseHandle(snapshot);
    return processID;
}

bool InjectDLL(DWORD processID, const std::string& dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, processID);
    if (!hProcess) {
        MessageBox(NULL, "Failed to open target process.", "Error", MB_ICONERROR);
        return false;
    }

    LPVOID allocatedMem = VirtualAllocEx(hProcess, NULL, dllPath.size() + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!allocatedMem) {
        MessageBox(NULL, "Memory allocation in target process failed.", "Error", MB_ICONERROR);
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, allocatedMem, dllPath.c_str(), dllPath.size() + 1, NULL)) {
        MessageBox(NULL, "Failed to write DLL path to target process memory.", "Error", MB_ICONERROR);
        VirtualFreeEx(hProcess, allocatedMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, allocatedMem, 0, NULL);
    if (!hThread) {
        MessageBox(NULL, "Failed to create remote thread in target process.", "Error", MB_ICONERROR);
        VirtualFreeEx(hProcess, allocatedMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, allocatedMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    MessageBox(NULL, "DLL injected successfully!", "Success", MB_ICONINFORMATION);
    return true;
}

int main() {
    const std::string targetProcess = "notepad.exe";
    std::string dllPath;

    DWORD processID = FindProcessID(targetProcess);
    if (!processID) {
        MessageBox(NULL, "Target process not found.", "Error", MB_ICONERROR);
        return EXIT_FAILURE;
    }

    if (!SelectDLL(dllPath)) {
        MessageBox(NULL, "DLL selection canceled or failed.", "Error", MB_ICONWARNING);
        return EXIT_FAILURE;
    }

    if (!InjectDLL(processID, dllPath)) {
        MessageBox(NULL, "DLL injection failed.", "Error", MB_ICONERROR);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
