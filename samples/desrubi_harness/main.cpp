#include <Windows.h>
#include <stdio.h>
#include <stdint.h>

extern "C" __declspec(dllexport) void target(void)
{

}

int main(void)
{
	target();
	return 0;
}