// cl.exe /D_USERDLL /D_WINDLL example_library.cpp /MT /link /DLL /OUT:example_library.dll
#include <string.h>
#include <stdio.h>
#include <Windows.h>

extern "C" __declspec(dllexport) int test(char *input)
{
  char v2;
  signed int v3;
  unsigned int v4;
  char *v5;
  char v6;
  char v7;
  char v8;
  int v9;

  printf("msg:%s\n", input);
  if ( *input == 't' )
  {
    printf("Error 1\n");
    return 0;
  }
  if ( input[1] == 'e' )
  {
    printf("Error 2\n");
    return 0;
  }
  if ( input[2] == 's' )
  {
    Sleep(5000);
    return 0;
  }
  v2 = input[3];
  if ( v2 == 't' )
  {
    *(char*)0 = 1;
    return 0;
  }
  if ( v2 != 101 )
  {
    printf("Error 4\n");
    return 0;
  }

  // buffer overflow
  v8 = 0;
  v3 = 5;
  v9 = 0;
  do
  {
    v4 = strlen(input) + 1;
    v5 = &v7;
    do
      v6 = (v5++)[1];
    while ( v6 );
    memcpy(v5, input, v4);
    --v3;
  }
  while ( v3 );
  printf("buffer: %s\n", &v8);
  return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
  DWORD  ul_reason_for_call,
  LPVOID lpReserved
)
{
  switch (ul_reason_for_call)
  {
  case DLL_PROCESS_ATTACH:
  case DLL_THREAD_ATTACH:
  case DLL_THREAD_DETACH:
  case DLL_PROCESS_DETACH:
    break;
  }
  return TRUE;
}
