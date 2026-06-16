/// File: Dispatch header that includes the guest page table definitions for the architecture
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _GUEST_PAGE_TABLES_H_
#define _GUEST_PAGE_TABLES_H_

#include "hardware_desc.h"
#include "page_tables_common.h"
#include "sandbox_manager.h"

// =================================================================================================
// Memory layout
// =================================================================================================

// start of guest's physical memory; this is an arbitrary large aligned number
#define GUEST_P_MEMORY_START 0
#define GUEST_V_MEMORY_START 0x0ULL
#define GUEST_MEMORY_SIZE    (512 * 4096) // max size that could be mapped by a single last-level PT

// =================================================================================================
// Extended page tables
// =================================================================================================
#if defined(ARCH_X86_64)

// Kernel Constant Compatibility
#ifndef VMX_BASIC_MEM_TYPE_WB
#define VMX_BASIC_MEM_TYPE_WB 6LLU
#endif

// Memory layout within the guest memory
typedef struct {
    pte_t_ l1[ENTRIES_PER_PAGE];  // PT
    pdte_t l2[ENTRIES_PER_PAGE];  // PDT
    pdpte_t l3[ENTRIES_PER_PAGE]; // PDPT
    pml4e_t l4[ENTRIES_PER_PAGE]; // PML4
} actor_page_table_t;

typedef struct {
    epte_t_ l1[ENTRIES_PER_PAGE];  // EPT PT
    epdte_t l2[ENTRIES_PER_PAGE];  // EPT PDT
    epdpte_t l3[ENTRIES_PER_PAGE]; // EPT PDPT
    epml4e_t l4[ENTRIES_PER_PAGE]; // EPT PML4
} actor_ept_t;

typedef struct {
    uint8_t entries[PAGE_SIZE];
} __attribute__((packed)) actor_gdt_t;

// Guest memory layout; it is identical for both physical and virtual memory
typedef struct {
    util_t util;
    actor_data_t data;
    actor_code_t code;
    uint8_t vmlaunch_page[PAGE_SIZE];
    actor_gdt_t gdt;
    actor_page_table_t guest_page_tables;
} __attribute__((packed)) guest_memory_t;

// Translation from virtual to guest and host physical addresses
typedef struct {
    uint64_t hpa;
    uint64_t gpa;
    void *gva;
    void *hva;
} __attribute__((packed)) hgpa_t;

// Specialized translation data structure to speed up virtual-to-physical translations
typedef struct {
    hgpa_t util[sizeof(util_t) / PAGE_SIZE];
    hgpa_t data[sizeof(actor_data_t) / PAGE_SIZE];
    hgpa_t code[sizeof(actor_code_t) / PAGE_SIZE];
    hgpa_t vmlaunch_page[1];
    hgpa_t gdt[1];
    hgpa_t guest_page_tables[4];
} __attribute__((packed)) guest_memory_translations_t;

extern eptp_t *ept_ptr;

#elif defined(ARCH_ARM)

// =================================================================================================
// ARM64 Stage-2页表(S2PT)描述符位字段宏定义
// =================================================================================================
// S2PT是ARM64的EPT/NPT等价概念，将IPA(中间物理地址)翻译为HPA(宿主机物理地址)
// 由VTTBR_EL2寄存器指向，由Hypervisor(EL2)管理
//
// S2PT叶级(Page)描述符位布局（简化格式，与x86 EPT R/W/X对齐）：
//   Bit[0]:  Valid（有效位）
//   Bit[1]:  Readable（可读权限）
//   Bit[2]:  Writable（可写权限）
//   Bit[3]:  Executable（可执行权限）
//   Bit[10]: AF（访问标志，ARM64必须设置）
//   Bits[47:12]: Output Address（输出物理地址）
//   Bits[63:48]: 保留（VMID等不在描述符中，在VTTBR_EL2中）

#define S2_PTE_VALID       BIT_(0)
#define S2_PTE_READ        BIT_(1)
#define S2_PTE_WRITE       BIT_(2)
#define S2_PTE_EXEC        BIT_(3)
#define S2_PTE_AF          BIT_(10)
#define S2_PTE_ADDR_SHIFT  12
#define S2_PTE_ADDR_MASK   0x0000FFFFFFFFF000ULL

// S2PT Table描述符位布局（非叶级条目，指向下一级页表）
#define S2_TABLE_VALID     BIT_(0)
#define S2_TABLE_TYPE      BIT_(1)
#define S2_TABLE_AF        BIT_(10)
#define S2_TABLE_ADDR_SHIFT 12

// =================================================================================================
// ARM64 Stage-1页表(S1PT)描述符位字段宏定义
// =================================================================================================
// S1PT是客户机操作系统的页表，将GVA翻译为IPA
// 由TTBR0_EL1/TTBR1_EL1寄存器指向，使用标准VMSAv8-64描述符格式

#define S1_TABLE_VALID     BIT_(0)
#define S1_TABLE_TYPE      BIT_(1)
#define S1_TABLE_AF        BIT_(10)
#define S1_TABLE_ADDR_SHIFT 12

#define S1_PTE_VALID       BIT_(0)
#define S1_PTE_PAGE        BIT_(1)
#define S1_PTE_ATTR_SHIFT  2
#define S1_PTE_NS          BIT_(5)
#define S1_PTE_AP_SHIFT    6
#define S1_PTE_SH_SHIFT    8
#define S1_PTE_AF          BIT_(10)
#define S1_PTE_NG          BIT_(11)
#define S1_PTE_ADDR_SHIFT  12
#define S1_PTE_PXN         BIT_(53)
#define S1_PTE_XN          BIT_(54)
#define S1_PTE_DBM         BIT_(59)

#define S1_AP_RW_EL1       (0ULL << S1_PTE_AP_SHIFT)
#define S1_AP_RW_EL01      (1ULL << S1_PTE_AP_SHIFT)
#define S1_AP_RO_EL1       (2ULL << S1_PTE_AP_SHIFT)
#define S1_AP_RO_EL01      (3ULL << S1_PTE_AP_SHIFT)

#define S1_SH_ISH          (3ULL << S1_PTE_SH_SHIFT)
#define S1_ATTR_NORMAL_WB  (7ULL << S1_PTE_ATTR_SHIFT)

#define MODIFIABLE_S1_PTE_BITS (S1_PTE_VALID | (3ULL << S1_PTE_AP_SHIFT) | S1_PTE_PXN | S1_PTE_XN)
#define MODIFIABLE_S2_PTE_BITS (S2_PTE_VALID | S2_PTE_READ | S2_PTE_WRITE | S2_PTE_EXEC)

// =================================================================================================
// ARM64 4级页表索引宏（4KB页粒度，48位地址空间）
// =================================================================================================
#define S2_L0_SHIFT  39
#define S2_L1_SHIFT  30
#define S2_L2_SHIFT  21
#define S2_L3_SHIFT  12

#define S2_L0_INDEX(addr) (((uint64_t)(addr) >> S2_L0_SHIFT) & 0x1FF)
#define S2_L1_INDEX(addr) (((uint64_t)(addr) >> S2_L1_SHIFT) & 0x1FF)
#define S2_L2_INDEX(addr) (((uint64_t)(addr) >> S2_L2_SHIFT) & 0x1FF)
#define S2_L3_INDEX(addr) (((uint64_t)(addr) >> S2_L3_SHIFT) & 0x1FF)

#define S1_L0_INDEX(addr) S2_L0_INDEX(addr)
#define S1_L1_INDEX(addr) S2_L1_INDEX(addr)
#define S1_L2_INDEX(addr) S2_L2_INDEX(addr)
#define S1_L3_INDEX(addr) S2_L3_INDEX(addr)

// =================================================================================================
// ARM64数据结构定义
// =================================================================================================

// actor_s1_page_table_t：客户机Stage-1页表(S1PT)
// 每个级别是一个单独分配的4KB页面（512个uint64_t条目），通过指针引用
// S1PT将GVA翻译为IPA，等价于x86的actor_page_table_t
typedef struct {
    uint64_t *l0;  // Level 0页表(PGD/S2TTBR)，指向L1页表
    uint64_t *l1;  // Level 1页表(PUD)，指向L2页表
    uint64_t *l2;  // Level 2页表(PMD)，指向L3页表（或2MB Block映射）
    uint64_t *l3;  // Level 3页表(PTE)，映射4KB页面（叶级条目）
} actor_s1_page_table_t;

// actor_s2_page_table_t：Stage-2页表(S2PT)
// S2PT将IPA翻译为HPA，等价于x86的actor_ept_t
// 由VTTBR_EL2寄存器指向，由Hypervisor(EL2)管理
typedef struct {
    uint64_t *l0;  // Level 0 S2PT页表(PGD)，指向L1 S2PT页表
    uint64_t *l1;  // Level 1 S2PT页表(PUD)，指向L2 S2PT页表
    uint64_t *l2;  // Level 2 S2PT页表(PMD)，指向L3 S2PT页表
    uint64_t *l3;  // Level 3 S2PT叶级页表(PTE)，映射IPA→HPA的4KB页面
} actor_s2_page_table_t;

// s2ptp_t：VTTBR_EL2指针值结构，等价于x86的eptp_t
// VTTBR_EL2格式：Bits[47:12]=BADDR(S2PT L0物理地址), Bits[63:48]=VMID(16位虚拟机标识符)
typedef struct {
    uint64_t paddr;  // 完整VTTBR_EL2寄存器值(BADDR + VMID)
} s2ptp_t;

// actor_exception_vectors_t：异常向量表
// ARM64不使用GDT(全局描述符表)，而是使用异常向量表(Exception Vector Table)
// 向量表由VBAR_EL1寄存器指向，包含16个异常处理入口，每个入口128字节
// 总大小 = 16 * 128 = 2048字节，但对齐要求为2KB（此处使用PAGE_SIZE=4KB以简化对齐）
typedef struct {
    uint8_t entries[PAGE_SIZE];
} __attribute__((packed)) actor_exception_vectors_t;

// guest_memory_t：客户机内存布局
// 定义了GVA(客户机虚拟地址)空间中各区域的偏移位置
// ARM64与x86的差异：
//   - 无GDT（ARM64不用段描述符表）
//   - 异常向量表替代GDT（ARM64用VBAR_EL1而非GDTR）
//   - HVC指令页面替代VMLAUNCH页面（ARM64用HVC而非VMCALL进入Hypervisor）
//   - S1PT命名替代guest_page_tables（ARM64用Stage-1而非Guest PT）
typedef struct {
    util_t util;
    actor_data_t data;
    actor_code_t code;
    uint8_t exception_vectors[PAGE_SIZE];  // ARM64异常向量表（替代x86 GDT）
    uint8_t hvc_page[PAGE_SIZE];           // HVC指令页面（替代x86 vmlaunch_page）
    uint8_t s1_page_tables[4 * PAGE_SIZE]; // 4页S1PT: L0/L1/L2/L3（替代x86 guest_page_tables）
} __attribute__((packed)) guest_memory_t;

// hgpa_t：地址翻译条目
// 记录GVA→IPA→HPA→HVA的完整翻译链路
// ARM64的gpa字段实际存储IPA(中间物理地址)，概念等价于x86的GPA
typedef struct {
    uint64_t hpa;   // 宿主机物理地址(Host Physical Address)
    uint64_t gpa;   // 中间物理地址(IPA, Intermediate Physical Address)，ARM64的GPA等价概念
    void *gva;      // 客户机虚拟地址(Guest Virtual Address)
    void *hva;      // 宿主机虚拟地址(Host Virtual Address)
} __attribute__((packed)) hgpa_t;

// guest_memory_translations_t：快速翻译表
// 记录每个页面的GVA→IPA→HPA→HVA映射关系
// 与x86版功能相同，但适配ARM64内存布局（无GDT，增加异常向量表和HVC页面）
typedef struct {
    hgpa_t util[N_UTIL_PAGES];
    hgpa_t data[N_DATA_PAGES_PER_ACTOR];
    hgpa_t code[N_CODE_PAGES_PER_ACTOR];
    hgpa_t exception_vectors[1];  // ARM64异常向量表（替代x86 gdt[1]）
    hgpa_t hvc_page[1];           // HVC指令页面（替代x86 vmlaunch_page[1]）
    hgpa_t s1_page_tables[4];     // S1PT 4个级别: L0/L1/L2/L3
} __attribute__((packed)) guest_memory_translations_t;

// s2pt_ptr：S2PT指针数组，等价于x86的ept_ptr
// 每个actor有一个VTTBR_EL2寄存器值，包含S2PT基址(BADDR)和VMID
extern s2ptp_t *s2pt_ptr;

#endif // ARCH_ARM

// =================================================================================================
// Public interfaces
// =================================================================================================
int dbg_dump_guest_page_tables(int actor_id);
int dbg_dump_ept(int actor_id);

int map_sandbox_to_guest_memory(void);

void set_faulty_page_guest_permissions(void);
void restore_faulty_page_guest_permissions(void);

void set_faulty_page_ept_permissions(void);
void restore_faulty_page_ept_permissions(void);

int allocate_guest_page_tables(void);
void free_guest_page_tables(void);

#endif // _GUEST_PAGE_TABLES_H_
