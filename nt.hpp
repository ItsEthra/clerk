#pragma once

struct UNICODE_STRING
{
    unsigned short Length;
    unsigned short MaximumLength;
    wchar_t* Buffer;
}; 

struct LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    void* DllBase;
    void* EntryPoint;
    unsigned long SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        unsigned char FlagGroup[4];
        unsigned long Flags;
        struct
        {
            unsigned long PackagedBinary:1;
            unsigned long MarkedForRemoval:1;
            unsigned long ImageDll:1;
            unsigned long LoadNotificationsSent:1;
            unsigned long TelemetryEntryProcessed:1;
            unsigned long ProcessStaticImport:1;
            unsigned long InLegacyLists:1;
            unsigned long InIndexes:1;
            unsigned long ShimDll:1;
            unsigned long InExceptionTable:1;
            unsigned long ReservedFlags1:2;
            unsigned long LoadInProgress:1;
            unsigned long LoadConfigProcessed:1;
            unsigned long EntryProcessed:1;
            unsigned long ProtectDelayLoad:1;
            unsigned long ReservedFlags3:2;
            unsigned long DontCallForThreads:1;
            unsigned long ProcessAttachCalled:1;
            unsigned long ProcessAttachFailed:1;
            unsigned long CorDeferredValidate:1;
            unsigned long CorImage:1;
            unsigned long DontRelocate:1;
            unsigned long CorILOnly:1;
            unsigned long ChpeImage:1;
            unsigned long ReservedFlags5:2;
            unsigned long Redirected:1;
            unsigned long ReservedFlags6:2;
            unsigned long CompatDatabaseProcessed:1;
        };
    };
    unsigned short ObsoleteLoadCount;
    unsigned short TlsIndex;
    LIST_ENTRY HashLinks;
    unsigned long TimeDateStamp;
    void* EntryPointActivationContext;
    void* Lock;
    void* DdagNode;
    LIST_ENTRY NodeModuleLink;
    void* LoadContext;
    void* ParentDllBase;
    void* SwitchBackContext;
}; 

struct PEB_LDR_DATA
{
    unsigned long Length;
    unsigned char Initialized;
    void* SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    void* EntryInProgress;
    unsigned char ShutdownInProgress;
    void* ShutdownThreadId;
}; 

struct PEB64
{
    unsigned char InheritedAddressSpace;
    unsigned char ReadImageFileExecOptions;
    unsigned char BeingDebugged;
    union
    {
        unsigned char BitField;
        struct
        {
            unsigned char ImageUsesLargePages:1;
            unsigned char IsProtectedProcess:1;
            unsigned char IsImageDynamicallyRelocated:1;
            unsigned char SkipPatchingUser32Forwarders:1;
            unsigned char IsPackagedProcess:1;
            unsigned char IsAppContainer:1;
            unsigned char IsProtectedProcessLight:1;
            unsigned char IsLongPathAwareProcess:1;
        };
    };
    unsigned char Padding0[4];
    unsigned long long Mutant;
    unsigned long long ImageBaseAddress;
    PEB_LDR_DATA* Ldr;
};
