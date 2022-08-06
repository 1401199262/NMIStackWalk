#include "stuff.h"

VOID HalSendNMI(PKAFFINITY_EX affinity)
{
	PVOID addr;
	UNICODE_STRING routineName;

	RtlInitUnicodeString(&routineName, L"HalSendNMI");
	addr = MmGetSystemRoutineAddress(&routineName);

	if (!addr) __debugbreak();

	( (VOID(__fastcall*)(PKAFFINITY_EX))addr )(affinity);
}
