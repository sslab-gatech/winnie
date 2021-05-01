#pragma once

#define FATAL(f, ...) {printf(f ": GLE=%d\n", ##__VA_ARGS__##, GetLastError()); getc(stdin); ExitProcess(0); }
