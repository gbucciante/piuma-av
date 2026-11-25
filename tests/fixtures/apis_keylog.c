/* Campione di TEST innocuo: importa API da keylogger/downloader senza usarle. */
#include <windows.h>
#include <urlmon.h>
int main(int argc, char **argv){
    if (argc > 1000) {
        SetWindowsHookExA(WH_KEYBOARD_LL, NULL, NULL, 0);
        GetAsyncKeyState(0);
        URLDownloadToFileA(NULL, "", "", 0, NULL);
        WinExec("", 0);
    }
    return 0;
}
