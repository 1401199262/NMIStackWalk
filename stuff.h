#pragma once

#include <intrin.h>

#include <ntifs.h>

#define NMI_CB_POOL_TAG 'BCmN'

//0xa8 bytes (sizeof)
typedef struct _KAFFINITY_EX
{
    USHORT Count;                                                           //0x0
    USHORT Size;                                                            //0x2
    ULONG Reserved;                                                         //0x4
    ULONGLONG Bitmap[20];                                                   //0x8
} KAFFINITY_EX, *PKAFFINITY_EX;

typedef struct _NMI_CONTEXT
{
    INT NumFired;
} NMI_CONTEXT, *PNMI_CONTEXT;

EXTERN_C INT64 HLP_SecInNs(INT64 ms);
EXTERN_C VOID HLP_DelayExecutionThread(INT64 ms);
EXTERN_C BOOLEAN HLP_FireNMI(INT core, PKAFFINITY_EX affinity);

EXTERN_C VOID KeInitializeAffinityEx(PKAFFINITY_EX affinity);
EXTERN_C VOID KeAddProcessorAffinityEx(PKAFFINITY_EX affinity, INT num);

EXTERN_C VOID HalSendNMI(PKAFFINITY_EX affinity);
EXTERN_C NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess,PVOID SourceAddress,PEPROCESS TargetProcess,PVOID TargetAddress,SIZE_T BufferSize,KPROCESSOR_MODE PreviousMode,PSIZE_T ReturnSize);
EXTERN_C __int64 __fastcall PsGetProcessSectionBaseAddress(__int64 a1);
EXTERN_C NTSTATUS NTAPI ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);


typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_ENTRY
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

#pragma warning(disable:4200)
typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;
	SYSTEM_MODULE_ENTRY Module[0];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

