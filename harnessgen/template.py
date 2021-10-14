
ASCII_BYTE = ' !"#\\$%&\'\\(\\)\\*\\+,-\\./0123456789:;<=>\\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\\[\\]\\^_`abcdefghijklmnopqrstuvwxyz\\{\\|\\}\\\\~\t'

# Directory structure
MAIN_TRACE   = 'cor1_1'
SECOND_TRACE = 'cor1_2'
DIFF_TRACE   = 'cor2_1'
INPUT1       = 'input1'
INPUT2       = 'input2'
FUNCTYPE     = 'functype'

HEADER = """
#include <stdio.h>
#include <string.h> 
#include <stdlib.h> 
#include <intrin.h>
#include <windows.h>
#include <tchar.h>
#include <strsafe.h>

#define dbg_printf (void)printf

// Macro to help to loading functions
#define LOAD_FUNC(h, n)                                 \\
    n##_func = (n##_func_t)GetProcAddress(h, #n);       \\
    if (!n##_func) {                                    \\
        dbg_printf("failed to load function " #n "\\n"); \\
        exit(1);                                        \\
    }                                                   

// Macro help creating unique nop functions
#define NOP(x)                                                      \\
    int nop##x() {                                                  \\
        dbg_printf("==> nop%d called, %p\\n", ##x, _ReturnAddress());\\
        return (DWORD)x;                                            \\
    }

HMODULE dlllib;

{typedef}

"""

FUZZME = """
void fuzz_me(char* filename){

{funcdef}

{harness}

}
"""

MAIN = """
int main(int argc, char ** argv)
{
    if (argc < 2) {
        printf("Usage %s: <input file>\\n", argv[0]);
        printf("  e.g., harness.exe input\\n");
        exit(1);
    }

    dlllib = LoadLibraryA("%s");
    if (dlllib == NULL){
        dbg_printf("failed to load library, gle = %d\\n", GetLastError());
        exit(1);
    }

    char * filename = argv[1];    
    fuzz_me(filename);    
    return 0;
}
""" 

"""
    LOAD_FUNC(dlllib, avformat_open_input);
    int ret_avformat_open_input = avformat_open_input_func(&ctx_org, filename, 0, &avformat_open_input_arg3);  // zeros: if pointer one page ==> copy original page to that page ==> if error
    dbg_printf("avformat_open_input: ret = %d\n", ret_avformat_open_input); // @jinho: check crash / progress
"""

FUNC = """    
    {print_cid}    
    LOAD_FUNC(dlllib, {funcname});
    {ret_statement}{funcname}_func({arguments});
    {dbg_printf} """

FUNC_WO = """    
    {print_cid}
    {ret_statement}{funcname}_func({arguments});
    {dbg_printf} """