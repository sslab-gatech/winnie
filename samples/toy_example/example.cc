// fuzz_me will typically be at 0x401000

#include <stdio.h>
#include <windows.h>
#include <conio.h>

#define DEBUG_LOG_FILE "toy_example.log"

#define dbg_printf (void)printf

typedef int (*test_func_t)(char*);
HMODULE hMathlib;

void check_fwrite()
{
    static int counter = 0;
    FILE *fp;
    fp = fopen(DEBUG_LOG_FILE, "a");
    fprintf(fp, "hello from toy example! counter value: %d\n", counter);
    fclose(fp);
    counter++;
}

void __stdcall fuzz_me(char* filename)
{
    char buf[201];
    ZeroMemory(&buf, 201);
    FILE *fp = fopen(filename, "rb");
    fread(buf, 1, 200, fp);

    test_func_t Math_test_func = (test_func_t) GetProcAddress(hMathlib, "test"); // index
    int result = Math_test_func(buf);      
    printf("Result: %d\n", result);    
    fclose(fp);  

    check_fwrite();

    TerminateProcess(INVALID_HANDLE_VALUE, 0); // Won't do anything
    printf("Bye");
    TerminateProcess(GetCurrentProcess(), 0); // Should get reported as exit
    printf("We should never get here");
}

int main(int argc, char ** argv)
{
    system("del " DEBUG_LOG_FILE);

    hMathlib = LoadLibraryA("example_library.dll");
    if (hMathlib == NULL) {
        dbg_printf("failed to load example_library , GLE = %d\n", GetLastError());
        exit(1);
    }
    printf("example_library loaded at %p\n", hMathlib);

    //_getch();

    fuzz_me(argv[1]);

    printf("main() ends\n");

    return 0;
}
