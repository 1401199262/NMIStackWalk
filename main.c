#include "stuff.h"

PVOID g_NmiCallbackHandle;
PKAFFINITY_EX g_NmiAffinity;
PNMI_CONTEXT g_NmiContext;
BOOLEAN StopDriver;
HANDLE SendNMIThreadHandle;
PVOID g_PageOfpStackWalkResult;

VOID SendNMIKernelRoutine(PVOID StartContext)
{
	UNREFERENCED_PARAMETER(StartContext);

	ULONG numCores = KeQueryActiveProcessorCountEx(0);

	while (!StopDriver)
	{
		for (ULONG i = 0; i < numCores; i++)
		{
			HLP_FireNMI(i, g_NmiAffinity); /* this will fire an NMI on CPU #i */
			HLP_DelayExecutionThread(200); /* can adjust this delay, it's been arbitrarily chosen. */
		}
		
		//have data in the stack walk record
		if (((DWORD64*)g_PageOfpStackWalkResult)[0] != 0)
		{
			PSYSTEM_MODULE_INFORMATION pSystemInfoBuffer = NULL;
			ULONG SystemInfoBufferSize = 0;
			NTSTATUS status = STATUS_SUCCESS;

			for (int i = 0; i < 0x1000 / 0x10; i += 2)
			{
				if (((DWORD64*)g_PageOfpStackWalkResult)[i] != 0)
				{
					//__debugbreak();
					if (MmIsAddressValid(((PVOID*)g_PageOfpStackWalkResult)[i]) && ((DWORD64*)g_PageOfpStackWalkResult)[i + 1])
					{
						// get all driver imagebase and size
						if (!pSystemInfoBuffer)
						{
							status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &SystemInfoBufferSize);
							if (!SystemInfoBufferSize)
							{
								__debugbreak();
							}

							pSystemInfoBuffer = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, (SIZE_T)SystemInfoBufferSize * 2, NMI_CB_POOL_TAG);
							if (!pSystemInfoBuffer)
							{
								__debugbreak();
							}

							memset(pSystemInfoBuffer, 0, (SIZE_T)SystemInfoBufferSize * 2);
							status = ZwQuerySystemInformation(SystemModuleInformation, pSystemInfoBuffer, (SIZE_T)SystemInfoBufferSize * 2, &SystemInfoBufferSize);
							if (!NT_SUCCESS(status))
							{
								__debugbreak();
							}
						}

						//iteriate through all frames in this stack record
						SIZE_T j = 0;
						for (j = 0; i < ((DWORD64*)g_PageOfpStackWalkResult)[i + 1]; j++)
						{
							BOOLEAN IsFrameInLegitModule = FALSE;
							ULONG64 CurrentFrameValue = (((DWORD64**)g_PageOfpStackWalkResult)[i])[j];

							// not kernel mode addr, skip
							if (CurrentFrameValue < 0xFFFF000000000000)
							{
								break;
							}

							//check and see if it is in a driver module
							for (ULONG ModuleCount = 0; ModuleCount < pSystemInfoBuffer->Count; ModuleCount++)
							{
								if (CurrentFrameValue >= (ULONG64)pSystemInfoBuffer->Module[ModuleCount].ImageBase &&
									CurrentFrameValue <= (ULONG64)pSystemInfoBuffer->Module[ModuleCount].ImageBase + pSystemInfoBuffer->Module[ModuleCount].ImageSize)
								{
									//this stack frame is legal
									IsFrameInLegitModule = TRUE;
									break;
								}
							}

							if (!IsFrameInLegitModule)
							{
								//report, todo: identiy PG's context
								//todo: verify more frame and check present of sensitive function
								DbgPrintEx(0, 0, "Detect shellcode outside of kernel module addr=%llx", CurrentFrameValue);

								if (!MmIsAddressValid(CurrentFrameValue))
								{
									DbgPrintEx(0, 0, ", shellcode address is not valid, maybe it is a PG context\n");
								}
								else
								{
									DbgPrintEx(0, 0, "\n");
								}

							}

						}
						
						ExFreePoolWithTag(((PVOID*)g_PageOfpStackWalkResult)[i], NMI_CB_POOL_TAG);
						((DWORD64*)g_PageOfpStackWalkResult)[i] = 0;
						((DWORD64*)g_PageOfpStackWalkResult)[i + 1] = 0;

					}
					else
					{
						((DWORD64*)g_PageOfpStackWalkResult)[i] = 0;
						((DWORD64*)g_PageOfpStackWalkResult)[i + 1] = 0;
					}
				}
			}

			if (pSystemInfoBuffer)
				ExFreePoolWithTag(pSystemInfoBuffer, NMI_CB_POOL_TAG);

		}

	}

	PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID WaitThreadTerminate(HANDLE ThreadHandle)
{
	if (ThreadHandle != NULL) {
		PETHREAD ThreadObject;

		if (NT_SUCCESS(ObReferenceObjectByHandle(ThreadHandle, THREAD_ALL_ACCESS, NULL, KernelMode, (PVOID*)(&ThreadObject), NULL)))
		{
			KeWaitForSingleObject((PVOID)(ThreadObject), Executive, KernelMode, FALSE, NULL);
			ObDereferenceObject((PVOID)(ThreadObject));
		}
	}
}

BOOLEAN StopDetectionThread() {
	StopDriver = TRUE;
	WaitThreadTerminate(SendNMIThreadHandle);
	return TRUE;
}

BOOLEAN NmiCallback(PVOID context, BOOLEAN handled)
{
	UNREFERENCED_PARAMETER(handled);
	
	PVOID* stackTrace = ExAllocatePoolWithTag(NonPagedPool, 0x1000, NMI_CB_POOL_TAG);
	if (!stackTrace)
	{
		__debugbreak();
		return TRUE;
	}

	USHORT capturedFrames = 0;
	capturedFrames = RtlCaptureStackBackTrace(0, 0x1000 / 8, stackTrace, NULL);

	BOOLEAN MmCopyFound = FALSE;
	MmCopyFound = TRUE;

	//for (USHORT i = 0; i < capturedFrames; i++)
	//{
	//	// in MmCopyVirtualMemory, todo determine the size
	//	if ((ULONG64)stackTrace[i] - *(ULONG64*)((ULONG64)context + 0x444) <= 0xE4B)
	//	{
	//		MmCopyFound = TRUE;
	//		break;
	//	}
	//}

	if (MmCopyFound)
	{
		//DbgPrintEx(0, 0, "Found MmCopy, insert into list\n");
		
		for (int i = 0; i < 0x1000 / 0x10; i += 2)
		{			
			if (((DWORD64*)g_PageOfpStackWalkResult)[i] == 0)
			{
				((DWORD64*)g_PageOfpStackWalkResult)[i] = (ULONG64)stackTrace;
				((DWORD64*)g_PageOfpStackWalkResult)[i + 1] = capturedFrames;
				break;
			}
		}
	}
	else
		ExFreePoolWithTag(stackTrace, NMI_CB_POOL_TAG);


	PNMI_CONTEXT cpuContext = &((PNMI_CONTEXT)context)[KeGetCurrentProcessorNumberEx(0)];
	++cpuContext->NumFired;

	return TRUE;
}

VOID DriverUnload(PDRIVER_OBJECT drvObj)
{
	UNREFERENCED_PARAMETER(drvObj);

	DbgPrintEx(0, 0, "[nmi_cb]  unload\n");

	ULONG numCores = KeQueryActiveProcessorCountEx(0);

	for (ULONG i = 0; i < numCores; i++)
	{
		PNMI_CONTEXT cpuContext = &g_NmiContext[i];

		DbgPrintEx(0, 0, "[nmi_cb]  CPU#%i NmiCallbackInvokes=%i\n", i, cpuContext->NumFired);
	}

	StopDetectionThread();

	if (g_NmiCallbackHandle) KeDeregisterNmiCallback(g_NmiCallbackHandle);
	if (g_NmiAffinity) ExFreePoolWithTag(g_NmiAffinity, NMI_CB_POOL_TAG);
	if (g_NmiContext) ExFreePoolWithTag(g_NmiContext, NMI_CB_POOL_TAG);
	if (g_PageOfpStackWalkResult) ExFreePoolWithTag(g_PageOfpStackWalkResult, NMI_CB_POOL_TAG);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drvObj, PUNICODE_STRING regPath)
{
	UNREFERENCED_PARAMETER(regPath);

	DbgPrintEx(0, 0, "\n[nmi_cb]  entry\n");

	drvObj->DriverUnload = DriverUnload;

	ULONG numCores = KeQueryActiveProcessorCountEx(0);
	ULONG nmiContextLength = numCores * sizeof(NMI_CONTEXT);

	g_NmiContext = (PNMI_CONTEXT)ExAllocatePoolWithTag(NonPagedPool, nmiContextLength, NMI_CB_POOL_TAG);

	g_NmiAffinity = ExAllocatePoolWithTag(NonPagedPool, sizeof(KAFFINITY_EX), NMI_CB_POOL_TAG);
	g_PageOfpStackWalkResult = ExAllocatePoolWithTag(NonPagedPool, 0x1000, NMI_CB_POOL_TAG);

	g_NmiCallbackHandle = KeRegisterNmiCallback(NmiCallback, g_NmiContext);

	if (!g_NmiAffinity || !g_NmiContext || !g_NmiCallbackHandle || !g_PageOfpStackWalkResult)
		return STATUS_FAILED_DRIVER_ENTRY;

	memset(g_NmiContext, 0, nmiContextLength);
	memset(g_PageOfpStackWalkResult, 0, 0x1000);

	UNICODE_STRING FunName;
	RtlInitUnicodeString(&FunName, L"MmCopyVirtualMemory");
	*(ULONG64*)((ULONG64)g_NmiContext + 0x444) = (ULONG64)MmGetSystemRoutineAddress(&FunName);

	StopDriver = FALSE;
	PsCreateSystemThread(&SendNMIThreadHandle, 0, NULL, NULL, NULL, &SendNMIKernelRoutine, NULL);

	return STATUS_SUCCESS;
}
