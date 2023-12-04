#include "nt.h"

extern ZwMapViewOfSection_t o_ZwMapViewOfSection;
NTSTATUS Hk_ZwMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, 
        PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);

extern ZwUnmapViewOfSection_t o_ZwUnmapViewOfSection;
void Hk_ZwUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);

extern ExitProcess_t o_ExitProcess;
void Hk_ExitProcess(UINT uExitCode);

void InstallHooks();