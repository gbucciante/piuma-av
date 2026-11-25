/* Campione di TEST innocuo: importa le API tipiche dell'iniezione ma non le esegue mai. */
#include <windows.h>
int main(int argc, char **argv){
    if (argc > 1000) {  /* mai vero */
        HANDLE h = OpenProcess(0, FALSE, 0);
        void *p = VirtualAllocEx(h, NULL, 1, MEM_COMMIT, PAGE_READWRITE);
        WriteProcessMemory(h, p, "", 0, NULL);
        CreateRemoteThread(h, NULL, 0, NULL, NULL, 0, NULL);
        if (IsDebuggerPresent()) GetTickCount();
    }
    return 0;
}
