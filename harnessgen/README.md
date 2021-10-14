# Harness Generator

## Library installation (tested with VS2017 and VS2019)

- Install required python packages

```sh
python3 -m pip install -r requirements.txt
```

- Install pintools

```sh
cd {repo}/lib
wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.13-98189-g60a6ef199-msvc-windows.zip
unzip pin-3.13-98189-g60a6ef199-msvc-windows.zip
mv pin-3.13-98189-g60a6ef199-msvc-windows pin
rm -f pin-3.13-98189-g60a6ef199-msvc-windows.zip
```

- Copy the tracer source code to pintools

```sh
cd {repo}/lib
cp -r Tracer pin/source/tools
```

- Compile the tracer (with pintools)
  - Open Tracer.sln with visual studio
  - Open library_trace.cpp and modify `_WINDOWS_H_PATH_` to a proper path (line 2)
  - If you are using VS2017, you should modify platform toolset (under Property - General - Platform Toolset)
  - Build the solution
  - Test

## Collect Dynamic Run Traces & Harness generation

Then we run a program with PIN-based tracer to
- infer (LCA analysis)

### One trace

```sh
# Trace API calls
pin.exe -t source/tools/Tracer/Release/Tracer.dll ^
  -logdir "cor1_1" -trace_mode "all" ^
  -only_to_target "test.exe" -only_to_lib "test.dll" ^
  -- test.exe input1

# Run harness synthesizer on single trace which starts from START_FUNCTION(...)
python3 synthesizer.py harness -t cor1_1/drltrace.PID.log -d cor1_1/memdump -s START_FUNCTION
```

#### Result example

```c++
#include <stdio.h>
...
typedef int (__stdcall *IDP_Init_func_t)(int);
typedef int (__stdcall *IDP_GetPlugInInfo_func_t)(int);
...

void fuzz_me(char* filename){

    IDP_Init_func_t IDP_Init_func;
    IDP_GetPlugInInfo_func_t IDP_GetPlugInInfo_func;
...

    /* Harness function #0 */
    int* c0_a0 = (int*) calloc (4096, sizeof(int));    
    LOAD_FUNC(dlllib, IDP_Init);
    int IDP_Init_ret = IDP_Init_func(&c0_a0);
    dbg_printf("IDP_Init, ret = %d\n", IDP_Init_ret); 
    
    /* Harness function #1 */
    int* c1_a0 = (int*) calloc (4096, sizeof(int));    
    LOAD_FUNC(dlllib, IDP_GetPlugInInfo);
    int IDP_GetPlugInInfo_ret = IDP_GetPlugInInfo_func(&c1_a0);
    dbg_printf("IDP_GetPlugInInfo, ret = %d\n", IDP_GetPlugInInfo_ret); 

...
    /* Harness function #66 */
    int* c66_a0 = (int*) calloc (4096, sizeof(int));    
    LOAD_FUNC(dlllib, IDP_CloseImage);
    int IDP_CloseImage_ret = IDP_CloseImage_func(&c66_a0);
    dbg_printf("IDP_CloseImage, ret = %d\n", IDP_CloseImage_ret); 

}


int main(int argc, char ** argv)
{
    if (argc < 2) {
        printf("Usage %s: <input file>\n", argv[0]);
        printf("  e.g., harness.exe input\n");
        exit(1);
    }

    dlllib = LoadLibraryA("%s");
    if (dlllib == NULL){
        dbg_printf("failed to load library, gle = %d\n", GetLastError());
        exit(1);
    }

    char * filename = argv[1];    
    fuzz_me(filename);    
    return 0;
}
```

### One correct + one incorrect

- Run the same tracer with the same input, but with `-logdir "cor1_2"`.
- Then run the same tracer with a different input, but with `-logdir "cor2_1"`.

```sh
# Trace API calls
pin.exe -t source/tools/Tracer/Release/Tracer.dll ^
  -logdir "cor1_2" -trace_mode "all" ^
  -only_to_target "test.exe" -only_to_lib "test.dll" ^
  -- test.exe input1

# Trace API calls
pin.exe -t source/tools/Tracer/Release/Tracer.dll ^
  -logdir "cor2_1" -trace_mode "all" ^
  -only_to_target "test.exe" -only_to_lib "test.dll" ^
  -- test.exe input2

# Run harness synthesizer on single trace which starts from START_FUNCTION(...)
python3 syn-multi.py harness -t ./ -s START_FUNCTION
```

### LCA Analysis

```sh
# Trace API calls
# - from test.exe -> test.dll (API)
# - file-related APIs (CreateFile, ...)
mkdir dom
pin.exe -t source/tools/Tracer/Release/Tracer.dll ^
  -logdir "dom" -trace_mode "dominator" ^
  -only_to_target "test.exe" -only_to_lib "test.dll" ^
  -- test.exe

# Do LCA analysis with API call traces between CreateFileW ~ CloseHandle
python3 dominator.py -s CreateFileW -e CloseHandle -sample "" -t ./dom/drltrace.PID.log -d ./dom/memdump/
```

#### Result example

```
[*] Displaying Most Frequent Address (Dominator candidates)
 >> Total unique harness functions: 400
 >> Total number of function address identified: 223
 >> Total number of candidate address(es): 4

[*] Dominator analysis
 >> Bad candidate (called multiple times): 0xc7c925
 >> Good candidate (called only once): 0xc579fb, 0xc5857f, 0xc56820
 >> Candidate address (sorted by the distance from harness): 0xc579fb, 0xc5857f, 0xc56820
```

### Troubleshooting

- The three synthesizers (synthesizer.py, syn-multi.py, dominator.py) utilizes static analyzer (e.g., IDA Pro).
  If it fails to find IDA Pro, try adjusting `IDA_PATH` in harconf.py.

