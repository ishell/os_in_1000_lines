#pragma once

#include "common.h"

struct sbiret
{
    long error;
    long value;
};

struct trap_frame
{
    uint32_t ra;
    uint32_t gp;
    uint32_t tp;
    uint32_t t0;
    uint32_t t1;
    uint32_t t2;
    uint32_t t3;
    uint32_t t4;
    uint32_t t5;
    uint32_t t6;
    uint32_t a0;
    uint32_t a1;
    uint32_t a2;
    uint32_t a3;
    uint32_t a4;
    uint32_t a5;
    uint32_t a6;
    uint32_t a7;
    uint32_t s0;
    uint32_t s1;
    uint32_t s2;
    uint32_t s3;
    uint32_t s4;
    uint32_t s5;
    uint32_t s6;
    uint32_t s7;
    uint32_t s8;
    uint32_t s9;
    uint32_t s10;
    uint32_t s11;
    uint32_t sp;
} __attribute__((packed));

struct process
{
    int pid;    // 进程ID
    int state;  // 进程状态: PROC_UNUSED, PROC_RUNNABLE
    vaddr_t sp; // 栈指针
    uint32_t *page_table;
    uint8_t stack[8192]; // 内核栈
};

struct sbiret sbi_call(long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, long fid, long eid)
{
    register long a0 __asm__("a0") = arg0;
    register long a1 __asm__("a1") = arg1;
    register long a2 __asm__("a2") = arg2;
    register long a3 __asm__("a3") = arg3;
    register long a4 __asm__("a4") = arg4;
    register long a5 __asm__("a5") = arg5;
    register long a6 __asm__("a6") = fid;
    register long a7 __asm__("a7") = eid;

    __asm__ __volatile__("ecall"
                         : "=r"(a0), "=r"(a1)
                         : "r"(a0), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5), "r"(a6), "r"(a7)
                         : "memory");
    return (struct sbiret){.error = a0, .value = a1};
}

#define SATP_SV32 (1u << 31)
#define PAGE_V (1 << 0) // "Valid" 位(表项已启用)
#define PAGE_R (1 << 1) // 可读
#define PAGE_W (1 << 2) // 可写
#define PAGE_X (1 << 3) // 可执行
#define PAGE_U (1 << 4) // 用户(用户模式可访问)

#define READ_CSR(reg)                                         \
    ({                                                        \
        unsigned long __tmp;                                  \
        __asm__ __volatile__("csrr %0, " #reg : "=r"(__tmp)); \
        __tmp;                                                \
    })

#define WRITE_CSR(reg, value)                                   \
    do                                                          \
    {                                                           \
        uint32_t __tmp = (value);                               \
        __asm__ __volatile__("csrw " #reg ", %0" ::"r"(__tmp)); \
    } while (0)

#define PANIC(fmt, ...)                                                       \
    do                                                                        \
    {                                                                         \
        printf("PANIC: %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
        while (1)                                                             \
        {                                                                     \
        }                                                                     \
    } while (0)