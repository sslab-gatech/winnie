// cl.exe /D_USERDLL /D_WINDLL DerusbiWrap.cpp /MT /link /DLL /OUT:DerusbiWrap.dll

#include <stdio.h>
#include <windows.h>
#include <conio.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment (lib, "Ws2_32.lib")

#include <harness-api.h>

EXPOSE_HARNESS(
    NULL,  // target method, we will fill this in dynamically at DllMain
    NULL,  // fuzz iter func, we will fill this in dynamically at DllMain
    NULL,  // default input file (.cur_input)
    NULL,  // no setup func needed
    TRUE,  // use de-socket features
    FALSE  // Not ready yet, we initialize dynamically in DllMain.
);

HMODULE hMod;

extern "C" __declspec(dllexport) 
void fuzz_me(void){
    FARPROC pFun;
    DWORD dwRet=0;  

    uint32_t v11[4];
    v11[0] = 0x5e58186c;
    v11[1] = 0xbaadf00d;    
    v11[2] = 0;
    v11[3] = 0;
    v11[4] = 0;

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0)
    {
        printf("Failed. Error Code : %d",WSAGetLastError());
        return;
    } 
    uint32_t* v12 = v11;    
    
    typedef void func(void);
    func* f = (func*)((uint32_t)hMod + 0x5de0);
    __asm {
        mov edi, v12
    }
    f();
    
    printf("Finished\n");
}

int WINAPI DoSetup(void* param) {
    hMod = LoadLibraryA("dfb8.dll");

    HarnessInfo.target_method = (LPVOID) GetProcAddress(GetModuleHandle(NULL), "target");
    HarnessInfo.fuzz_iter_func = (void(CALLBACK *)(void)) fuzz_me;

    MemoryBarrier(); // Prevent the compiler from messing things up by reordering.
    InterlockedExchange8(&HarnessInfo.ready, TRUE); // Signal to forkserver that we're ready to go.

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
) {
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DoSetup(NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
          break;
    }
    return TRUE;
}
