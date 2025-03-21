#include <iostream>
#include <windows.h>
#include <intrin.h>
#include <stdint.h>

LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION) {
        std::cout << "Privileged instruction detected! Handling the exception..." << std::endl;

        ExceptionInfo->ContextRecord->Rip += 3; // Skip the faulty instruction (64-bit)

        // Continue execution
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // Pass on other exceptions
    return EXCEPTION_CONTINUE_SEARCH;
}

int NewKiUserExceptionDispatcher(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context)
{   
    //log exception, the exception will be logged here first instead in VectoredExceptionHandler()
    printf("caught exception: 0x%lx at 0x%p\n",ExceptionRecord->ExceptionCode,ExceptionRecord->ExceptionAddress);
    return 0;
}


int main(){

    AddVectoredExceptionHandler(1, VectoredExceptionHandler);

    uintptr_t kiuserexceptiondispatcher = (uintptr_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "KiUserExceptionDispatcher");

    printf("KiUserExceptionDispatcher addr: 0x%llx\n",kiuserexceptiondispatcher);
    printf("NewKiUserExceptionDispatcher addr: 0x%llx\n",(uintptr_t)&NewKiUserExceptionDispatcher);

    uint8_t* buffer = (uint8_t*)malloc(12);

    // mov rax, &NewKiUserExceptionDispatcher
    buffer[0] = 0x48;
    buffer[1] = 0xB8;

    for (int i = 0; i < 8; i++) {
        buffer[i+2] = (uintptr_t(&NewKiUserExceptionDispatcher) >> (i * 8)) & 0xFF;
    }

    // two nops
    buffer[10] = 0x90; 
    buffer[11] = 0x90;

    printf("Assembled instruction: ");
    for (int i = 0; i < 12; i++) {
        printf("%02X ", buffer[i]);
    }
    printf("\n");


    // +1 to skip cld instruction
    //change memory protections

    DWORD oldprotect;
    VirtualProtect(reinterpret_cast<void*>(kiuserexceptiondispatcher+1),12,PAGE_EXECUTE_READWRITE,&oldprotect);
    //patch
    memcpy(reinterpret_cast<void*>(kiuserexceptiondispatcher+1),buffer,12);
    //revert memory protections
    VirtualProtect(reinterpret_cast<void*>(kiuserexceptiondispatcher+1),12,oldprotect,&oldprotect);
    

    std::cout << "Enter to cause exception! "; 
    std::cin.get();
    
    __writecr3(0x0);
        
    printf("Hello world!");

}