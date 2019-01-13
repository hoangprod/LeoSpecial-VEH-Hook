#include "LeoSpecial.h"
#include <time.h>

void(WINAPI *o_Sleep)(DWORD dwMilliseconds) = Sleep;


void hk_sleep(DWORD dwMilliseconds)
{
	printf("Hooked! Removing %d worth of sleep!\n", dwMilliseconds);
	return;
}

int main()
{
	//Hook codes!
	LeoHook Leo;
	if (!Leo.Hook((uintptr_t)Sleep, (uintptr_t)hk_sleep))
		printf("[-] Failed to hook...\n");

	double time_spent = 0.0;
	clock_t begin = clock();

	//Hooked
	Sleep(100000);


	clock_t end = clock();
	time_spent += (double)(end - begin) / CLOCKS_PER_SEC;
	printf("Time elpased is %f seconds\n", time_spent);

	//Unhook
	if (!Leo.Unhook())
		printf("[-] Failed to unhook...\n");

	time_spent = 0.0;
	begin = clock();

	Sleep(1000);


	end = clock();
	time_spent += (double)(end - begin) / CLOCKS_PER_SEC;
	printf("Time elpased is %f seconds\n", time_spent);


	std::cin.get();
    return 0;
}


