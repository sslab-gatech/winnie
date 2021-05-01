# Toy example target program for fuzzing

```
afl-fuzz -i in -o out -t 1000 -F basicblock.bb -- -fork -debug -harness harness.dll -init_time 1000 -- toy_example.exe @@
```
