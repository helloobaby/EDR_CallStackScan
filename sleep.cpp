// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <intrin.h>
#include <vector>


void* BaseThreadInitThunk = nullptr;
void* BaseThreadInitThunkEnd = nullptr;
std::vector<ULONG_PTR> StackFrame;
void SaveCallStack(ULONG_PTR* rsp) {
  ULONG_PTR* t = rsp;
  while (1) {
    StackFrame.push_back(*t);
    if (*t > (ULONG_PTR)BaseThreadInitThunk &&
        *t < (ULONG_PTR)BaseThreadInitThunkEnd) {
      break;
    }
    t = t + 1;
  }

  return;
}

void RestoreCallStack(ULONG_PTR* rsp) {
  for (int i = 0; i < StackFrame.size(); i++) {
    ULONG_PTR* t = rsp;
    *t = StackFrame[i];
  }
};

void ZeroCallStack(ULONG_PTR* rsp) {
  
    for (int i = 0; i < StackFrame.size(); i++) {
    *(rsp+i) = 0;
    }

};

void MySleep(DWORD dwMilliseconds) {
  ULONG_PTR* AddressOfReturnAddress = (ULONG_PTR*)_AddressOfReturnAddress();
  ULONG_PTR* Rsp = AddressOfReturnAddress;
  SaveCallStack(Rsp);
  ZeroCallStack(Rsp);
  Sleep(100000);
  RestoreCallStack(Rsp);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {
      BaseThreadInitThunk =
          GetProcAddress(LoadLibraryA("kernel32.dll"), "BaseThreadInitThunk");

      for (int i = 0; i < 10000; i++) {
        unsigned char* t = (unsigned char*)BaseThreadInitThunk + i;
        if (*t == 0xc3) {  // ret
          BaseThreadInitThunkEnd = t;
          break;
        }
      }

      MySleep(100000);
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

