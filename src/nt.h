#include <windows.h>
#include <winternl.h>

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

typedef NTSTATUS(NTAPI* ZwMapViewOfSection_t)(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID           *BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG           AllocationType,
    ULONG           Win32Protect
);

typedef NTSTATUS (NTAPI* ZwUnmapViewOfSection_t)(
  HANDLE ProcessHandle,
  PVOID  BaseAddress
);

typedef void (*ExitProcess_t)(
  UINT uExitCode
);