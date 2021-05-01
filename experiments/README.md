# experiments

This directory contains miscellaneous standalone projects used to test individual components of the fuzzer.

 - **CreateUserProcess_benchmark** -- forklib benchmark
 - **debugger** -- runtime tracer using debug API
 - **dump_parser** -- minidump parser
 - **hook-example** -- driver for the injected forkserver that tests hooking, forkserver, coverage, etc. without full fuzzer functionality
 - **test_fork_with_pt** -- forklib + parent-traces-child with Intel PT

The easiest way to build these examples is just to move them to the top-level directory and add them to the solution.
