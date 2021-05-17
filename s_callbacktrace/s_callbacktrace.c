//
//  s_callbacktrace.cpp
//  MachTaskDemo
//
//  Created by sunner on 2021/5/17.
//

#import "s_callbacktrace.h"
#import <pthread/pthread.h>
#import <limits.h>
#import <mach/mach.h>
#import <mach-o/nlist.h>
#import <mach-o/dyld.h>
#import <sys/types.h>
#import <stdio.h>

#if defined(__arm64__)
//#define DETAG_PC_ADDR(A) ((A) & ~(3UL))
#define S_THREAD_STATE_FLAVOR ARM_THREAD_STATE64
#define S_THREAD_STATE_COUNT ARM_THREAD_STATE64_COUNT
#define S_FP __fp
#define S_SP __sp
#define S_PC __pc

#elif defined(__arm__)
//#define DETAG_PC_ADDR(A) ((A) & ~(1UL))
#define S_THREAD_STATE_FLAVOR ARM_THREAD_STATE
#define S_THREAD_STATE_COUNT ARM_THREAD_STATE_COUNT
#define S_FP __r[7]
#define S_SP __sp
#define S_PC __pc

#elif defined(__x86_64__)
//#define DETAG_PC_ADDR(A) (A)
#define S_THREAD_STATE_FLAVOR x86_THREAD_STATE64
#define S_THREAD_STATE_COUNT x86_THREAD_STATE64_COUNT
#define S_FP __rbp
#define S_SP __rsp
#define S_PC __rip

#elif defined(__i386__)
//#define DETAG_PC_ADDR(A) (A)
#define S_THREAD_STATE_FLAVOR x86_THREAD_STATE32
#define S_THREAD_STATE_COUNT x86_THREAD_STATE32_COUNT
#define S_FP __ebp
#define S_SP __esp
#define S_PC __eip
#endif

#define S_FAILED_UINT_PTR_ADDR 0
#define S_MAX_FRAME_COUNT 50


struct stack_frame_entry {
    uintptr_t fp;
    uintptr_t rt;
};

struct symbol_info {
    uint64_t addr;
    uint64_t offset;
    const char *symbol;
    const char *fname;
};

void get_stack_frame_entrys(task_inspect_t task, thread_t thread, uintptr_t *callbacktrace_buffer, uint32_t *size) {
    _STRUCT_MCONTEXT machine_context;
    mach_msg_type_number_t state_count = S_THREAD_STATE_COUNT;
    thread_state_flavor_t flavor = S_THREAD_STATE_FLAVOR;
    kern_return_t kr = thread_get_state(thread, flavor, (thread_state_t)&((&machine_context)->__ss), &state_count);
    if (kr != KERN_SUCCESS) return;
    
    uint32_t idx = 0;
    uintptr_t pc = (&machine_context)->__ss.S_PC;
    if (pc == S_FAILED_UINT_PTR_ADDR) return;
    callbacktrace_buffer[idx++] = pc;
    
#if defined(__i386__) || defined(__x86_64__)
    uintptr_t lr = S_FAILED_UINT_PTR_ADDR;
#else
    uintptr_t lr = (&machine_context)->__ss.__lr;
#endif
    if (lr != S_FAILED_UINT_PTR_ADDR) {
        callbacktrace_buffer[idx++] = lr;
    }
    
    uintptr_t fp = (&machine_context)->__ss.S_FP;
    if (fp == S_FAILED_UINT_PTR_ADDR) return;
    
    struct stack_frame_entry sfe = {fp, 0};
    while (idx < S_MAX_FRAME_COUNT) {
        vm_size_t outsize = 0;
        uintptr_t addr = sfe.fp;
        kr = vm_read_overwrite(task, addr, sizeof(sfe), (vm_address_t)&sfe, &outsize);
        if (kr != KERN_SUCCESS || sfe.fp == 0 || sfe.rt == 0) break;
        callbacktrace_buffer[idx++] = sfe.rt;
        *size = idx;
    }
}

uint32_t image_index_contains_addr(uintptr_t addr) {
    const uint32_t image_count = _dyld_image_count();
    for (uint32_t i = 0; i < image_count; i++) {
        const struct mach_header *header = _dyld_get_image_header(i);
        if (header == NULL) continue;;
        
        uintptr_t cmdptr = 0;
        if (header->magic == MH_MAGIC || header->magic == MH_CIGAM) {
            cmdptr = (uintptr_t)(((struct mach_header *)header) + 1);
        }
        else if (header->magic == MH_MAGIC_64 || header->magic == MH_CIGAM_64) {
            cmdptr = (uintptr_t)(((struct mach_header_64 *)header) + 1);
        }
        if (cmdptr == S_FAILED_UINT_PTR_ADDR) continue;
        
        // aslr slide
        uintptr_t aslr_slide = _dyld_get_image_vmaddr_slide(i);
        // convert to mach_addr
        uintptr_t mach_addr = addr - aslr_slide;
        for (uint32_t cmdi = 0; cmdi < header->ncmds; cmdi++) {
            struct load_command *loadptr = (struct load_command *)cmdptr;
            if (loadptr->cmd == LC_SEGMENT) {
                struct segment_command *segmentptr = (struct segment_command *)cmdptr;
                if (mach_addr >= segmentptr->vmaddr && mach_addr < segmentptr->vmaddr + segmentptr->vmsize) {
                    return i;
                }
            }
            else if (loadptr->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *segmentptr = (struct segment_command_64 *)cmdptr;
                if (mach_addr >= segmentptr->vmaddr && mach_addr < segmentptr->vmaddr + segmentptr->vmsize) {
                    return i;
                }
            }
            cmdptr += loadptr->cmdsize;
        }
    }
    return -1;
}

uintptr_t get_segment_base_addr(uint32_t image_index) {
    const struct mach_header *header = _dyld_get_image_header(image_index);
    if (header == NULL) return 0;
    
    uintptr_t cmdptr = 0;
    if (header->magic == MH_MAGIC || header->magic == MH_CIGAM) {
        cmdptr = (uintptr_t)(((struct mach_header *)header) + 1);
    }
    else if (header->magic == MH_MAGIC_64 || header->magic == MH_CIGAM_64) {
        cmdptr = (uintptr_t)(((struct mach_header_64 *)header) + 1);
    }
    if (cmdptr == S_FAILED_UINT_PTR_ADDR) return 0;
    
    for (uint32_t cmdi = 0; cmdi < header->ncmds; cmdi++) {
        struct load_command *loadptr = (struct load_command *)cmdptr;
        if (loadptr->cmd == LC_SEGMENT) {
            struct segment_command *segmentptr = (struct segment_command *)cmdptr;
            if (strcmp(segmentptr->segname, SEG_LINKEDIT) == 0) {
                return segmentptr->vmaddr - segmentptr->fileoff;
            }
        }
        else if (loadptr->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *segmentptr = (struct segment_command_64 *)cmdptr;
            if (strcmp(segmentptr->segname, SEG_LINKEDIT) == 0) {
                return segmentptr->vmaddr - segmentptr->fileoff;
            }
        }
        cmdptr += loadptr->cmdsize;
    }
    return 0;
}

bool get_info(uint32_t image_index, uintptr_t addr, uintptr_t segment_base_addr, uintptr_t aslr_slide, struct symbol_info *info) {
    const struct mach_header *header = _dyld_get_image_header(image_index);
    if (header == NULL) return false;
    
    uintptr_t cmdptr = 0;
    if (header->magic == MH_MAGIC || header->magic == MH_CIGAM) {
        cmdptr = (uintptr_t)(((struct mach_header *)header) + 1);
    }
    else if (header->magic == MH_MAGIC_64 || header->magic == MH_CIGAM_64) {
        cmdptr = (uintptr_t)(((struct mach_header_64 *)header) + 1);
    }
    if (cmdptr == S_FAILED_UINT_PTR_ADDR) return false;
    
    struct symtab_command *symtabptr = 0;
    for (uint32_t cmdi = 0; cmdi < header->ncmds; cmdi++) {
        struct load_command *loadptr = (struct load_command *)cmdptr;
        if (loadptr->cmd == LC_SYMTAB) {
            symtabptr = (struct symtab_command *)cmdptr;
        }
        cmdptr += loadptr->cmdsize;
    }
    if (symtabptr == S_FAILED_UINT_PTR_ADDR) return false;
    
#if defined(__LP64__)
    struct nlist_64 *symbols = (struct nlist_64 *)(symtabptr->symoff + segment_base_addr);
#else
    struct nlist *symbols = (nlist *)(symtabptr->symoff + segment_base_addr);
#endif
    uintptr_t strings = segment_base_addr + symtabptr->stroff;

    uint64_t offset = UINT64_MAX;
    uintptr_t non_silde_addr = addr - aslr_slide;
    int best = -1;
    for (uint32_t i = 0; i < symtabptr->nsyms; i++) {
        uint64_t distance = non_silde_addr - symbols[i].n_value;
        if (non_silde_addr >= symbols[i].n_value && distance <= offset) {
            offset = distance;
            best = i;
        }
    }
    
    if (best == -1) return false;
    
    info->fname = _dyld_get_image_name(image_index);
    info->symbol = (char *)(intptr_t)strings + (intptr_t)symbols[best].n_un.n_strx;
    info->addr = symbols[best].n_value + aslr_slide;
    info->offset = offset;
    if (info->fname == NULL || strcmp(info->fname, "") == 0) {
        info->fname = "???";
    }
    if (info->symbol == NULL || strcmp(info->symbol, "") == 0) {
        info->symbol = "???";
    }
    if (*info->symbol == '_') {
        info->symbol++;
    }
    
    return true;
}

void symbolicate(uintptr_t *callbacktrace_buffer, uint32_t size, struct symbol_info *symbols_buffer, uint32_t *outsize) {
    uint32_t idx = 0;
    for (uint32_t i = 0; i < size; i++) {
        uintptr_t addr = callbacktrace_buffer[i];
        uint32_t image_index = image_index_contains_addr(addr);
        if (image_index == -1) continue;
        uintptr_t aslr_slide = _dyld_get_image_vmaddr_slide(image_index);
        uintptr_t segment_base_addr = get_segment_base_addr(image_index) + aslr_slide;
        if (segment_base_addr == S_FAILED_UINT_PTR_ADDR) continue;
        struct symbol_info info;
        bool success = get_info(image_index, addr, segment_base_addr, aslr_slide, &info);
        if (!success) continue;
        symbols_buffer[idx++] = info;
        *outsize = idx;
    }
}

void print_callbacktrace(task_inspect_t task, thread_t thread) {
    uintptr_t callbacktrace_buffer[S_MAX_FRAME_COUNT];
    uint32_t size = 0;
    get_stack_frame_entrys(task, thread, callbacktrace_buffer, &size);
    
    struct symbol_info symbols_buffer[S_MAX_FRAME_COUNT];
    uint32_t outsize = 0;
    symbolicate(callbacktrace_buffer, size, symbols_buffer, &outsize);
    
    if (mach_thread_self() == thread) {
        printf("\ncallbacktrace of main thread\n");
    } else {
        printf("\ncallbacktrace of thread: %ld\n", thread);
    }
    
    for (uint32_t i = 0; i < outsize; i++) {
        struct symbol_info info = symbols_buffer[i];
        const char *fname = strrchr(info.fname, '/') == NULL ? info.fname : strrchr(info.fname, '/') + 1;
        printf("%-30s %p   %s + %d\n", fname, info.addr, info.symbol, info.offset);
    }
}

void callbacktrace() {
    thread_act_array_t threads;
    mach_msg_type_number_t count;
    task_inspect_t task = mach_task_self();
    task_threads(mach_task_self(), &threads, &count);
    
    printf("\n 🐶🐶🐶🐶🐶🐶 callbacktrace start 🐶🐶🐶🐶🐶🐶🐶 \n");
    for (int i = 0; i < count; i++) {
        thread_t thread = threads[i];
        print_callbacktrace(task, thread);
    }
    printf("\n 🐶🐶🐶🐶🐶🐶  callbacktrace end  🐶🐶🐶🐶🐶🐶🐶 \n");
}




 
 
