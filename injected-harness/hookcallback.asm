include ksamd64.inc

EXTERNDEF __imp_RtlCaptureContext:QWORD
extern harness_main:proc
extern report_end:QWORD
extern savedContext:QWORD

.code

FuzzingHarness PROC
	add rsp, 8      ; discard return address
	push qword ptr [report_end] ; new retaddr

    push rcx                            ; preserve rcx
    lea rcx, qword ptr [savedContext]
    call __imp_RtlCaptureContext

    pop [rcx+CxRcx]                       ; 0x80 = offset of rcx

    lea rax, [rsp]                  ; calculate original rsp
    mov [rcx+CxRsp], rax                  ; 0x98 = offset of rsp

    sub rsp, 1020h  ; allocate a ton of space on the stack incl. shadow space

    jmp harness_main
FuzzingHarness ENDP

end
