#include "stuff.h"

INT64 HLP_SecInNs(INT64 ms)
{
	return (ms * 10000);
}

VOID HLP_DelayExecutionThread(INT64 ms)
{
	LARGE_INTEGER nDelay;
	memset(&nDelay, 0, sizeof(nDelay));

	nDelay.QuadPart -= HLP_SecInNs(ms);

	KeDelayExecutionThread(KernelMode, FALSE, &nDelay);
}

BOOLEAN HLP_FireNMI(INT core, PKAFFINITY_EX affinity)
{
	KeInitializeAffinityEx(affinity);
	KeAddProcessorAffinityEx(affinity, core);

	HalSendNMI(affinity);

	return TRUE;
}



