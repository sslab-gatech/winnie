#pragma once
#pragma warning(disable:4214)
#pragma warning(disable:4201)

//
// Requests that can be sent with IOCTL_IPT_REQUEST or IOCTL_IPT_READ_TRACE
//
typedef enum _IPT_INPUT_TYPE
{
    IptGetTraceVersion,
    IptGetProcessTraceSize,
    IptGetProcessTrace,                 // Use IOCTL_IPT_READ_TRACE
    IptStartCoreTracing,
    IptRegisterExtendedImageForTracing,
    IptStartProcessTrace,
    IptStopProcessTrace,
    IptPauseThreadTrace,
    IptResumeThreadTrace,
    IptQueryProcessTrace,
    IptQueryCoreTrace
} IPT_INPUT_TYPE, *PIPT_INPUT_TYPE;

//
// Header on top of any IOCTL Input Request
//
typedef struct _IPT_BUFFER_VERSION
{
    ULONG BufferMajorVersion;
    ULONG BufferMinorVersion;
} IPT_BUFFER_VERSION, *PIPT_BUFFER_VERSION;

//
// IOCTL Input Request Buffer
//
typedef struct _IPT_INPUT_BUFFER
{
    IPT_BUFFER_VERSION;
    IPT_INPUT_TYPE InputType;
    union
    {
        struct
        {
            USHORT TraceVersion;
            ULONG64 ProcessHandle;
        } GetProcessIptTraceSize;
        struct
        {
            USHORT TraceVersion;
            ULONG64 ProcessHandle;
        } GetProcessIptTrace;
        struct
        {
            IPT_OPTIONS Options;
            ULONG NumberOfTries;
            ULONG TraceDurationInSeconds;
        } StartCoreIptTracing;
        struct
        {
            IPT_OPTIONS Options;
            ULONG NumberOfTries;
            ULONG TraceDurationInSeconds;
            USHORT ImagePathLength;
            USHORT FilteredPathLength;
            WCHAR ImageName[ANYSIZE_ARRAY];
        } RegisterExtendedImageForIptTracing;
        struct
        {
            ULONG64 ProcessHandle;
            IPT_OPTIONS Options;
        } StartProcessIptTrace;
        struct
        {
            ULONG64 ProcessHandle;
        } StopProcessIptTrace;
        struct
        {
            ULONG64 ThreadHandle;
        } PauseThreadIptTrace;
        struct
        {
            ULONG64 ThreadHandle;
        } ResumeThreadIptTrace;
        struct
        {
            ULONG64 ProcessHandle;
        } QueryProcessIptTrace;
    };
} IPT_INPUT_BUFFER, *PIPT_INPUT_BUFFER;
C_ASSERT(sizeof(IPT_INPUT_BUFFER) == 0x28);

//
// IOCTL Output Request Buffer
//
typedef struct _IPT_OUTPUT_BUFFER
{
    union
    {
        struct
        {
            IPT_BUFFER_VERSION;
        } GetBufferMajorVersion;
        struct
        {
            USHORT TraceVersion;
        } GetTraceVersion;
        struct
        {
            USHORT TraceVersion;
            ULONGLONG TraceSize;
        } GetTraceSize;
        struct
        {
            IPT_TRACE_DATA;
        } GetTrace;
        struct
        {
            BOOLEAN OldState;
        } PauseTrace;
        struct
        {
            BOOLEAN OldState;
        } ResumeTrace;
        struct
        {
            IPT_OPTIONS Options;
        } QueryProcessTrace;
        struct
        {
            IPT_OPTIONS Options;
        } QueryCoreTrace;
    };
} IPT_OUTPUT_BUFFER, *PIPT_OUTPUT_BUFFER;
C_ASSERT(sizeof(IPT_OUTPUT_BUFFER) == 0x10);

//
// IOCTLs that the IPT Driver Handles
//
#define IOCTL_IPT_REQUEST \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IPT_READ_TRACE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 1, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

