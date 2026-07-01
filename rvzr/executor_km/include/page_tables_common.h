/// File: Dispatch header that includes the correct page tables definitions for the architecture
///
// ==============================================================================
// 页表公共定义头文件概述：
// 本文件定义了x86_64和ARM64架构的页表条目结构体，是虚拟化侧信道测试的基础。
//
// 页表结构体用于：
//   1. 构建宿主机的沙箱页表——控制测试代码和数据区域的访问权限
//      通过修改PTE/EPT权限位实现故障注入（如移除User位触发页故障）
//   2. 构建Guest的嵌套页表(EPT/NPT/Stage-2)——控制Guest Actor的内存访问
//      通过修改EPTE权限实现跨虚拟化边界的侧信道隔离/泄露
//   3. 动态修改页表权限——测试代码中的SET_DATA_PERMISSIONS宏
//      可在运行时修改数据区域的EPT/PTE权限位
//
// x86_64页表层级（四级页表）：
//   PML4 → PDPT → PD → PT → 4KB页
//   每级512个条目（因为PAGE_SIZE/sizeof(uint64_t) = 4096/8 = 512）
//
// x86_64扩展页表(EPT)层级（与常规页表类似，用于VMX虚拟化）：
//   EPML4 → EPDPT → EPD → EPT → 4KB页
//   EPT条目的权限位不同于常规PTE（使用Read/Write/Execute而非Present/RW/User）
//
// ARM64页表层级（四级页表，VMSAv8-64）：
//   L0 → L1 → L2 → L3 → 4KB页
//   使用不同的描述符格式（valid/type位区分表描述符和块描述符）
//
// MODIFIABLE_PTE_BITS定义了测试代码可以动态修改的PTE位，
// 这些位用于SET_DATA_PERMISSIONS宏实现运行时权限变更。
// ==============================================================================
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _PAGE_TABLES_COMMON_H_
#define _PAGE_TABLES_COMMON_H_

#include "hardware_desc.h"
#include <linux/slab.h> // PAGE_SIZE
#include <linux/types.h>

/// 每页条目数——一个页表中条目的数量
/// x86_64：4096/8 = 512条目/页表页
/// ARM64：4096/8 = 512条目/页表页
#define ENTRIES_PER_PAGE (PAGE_SIZE / sizeof(uint64_t))

// =================================================================================================
// x86_64架构页表定义
// =================================================================================================
#if defined(ARCH_X86_64)

/// 可修改的常规PTE位掩码——定义测试代码可以动态修改的PTE位
/// 包括：Present, RW, PWT, PCD, Accessed, Dirty, PKey(4位), NX, 和bit51
/// 这些位用于SET_DATA_PERMISSIONS宏，实现运行时页表权限变更
#define MODIFIABLE_PTE_BITS                                                                        \
    (_PAGE_PRESENT | _PAGE_RW | _PAGE_PWT | _PAGE_PCD | _PAGE_ACCESSED | _PAGE_DIRTY |             \
     _PAGE_PKEY_BIT0 | _PAGE_PKEY_BIT1 | _PAGE_PKEY_BIT2 | _PAGE_PKEY_BIT3 | _PAGE_NX |            \
     (1ULL << 51))

/// EPT扩展权限位定义——EPT使用不同于常规PTE的权限位
/// EPT权限：Present(读), RW(写), X(执行), Accessed, Dirty, User(用户模式执行)
#define _E_PAGE_PRESENT  (1 << 0)   // EPT读访问权限
#define _E_PAGE_RW       (1 << 1)   // EPT写访问权限
#define _E_PAGE_X        (1 << 2)   // EPT执行访问权限
#define _E_PAGE_ACCESSED (1 << 8)   // EPT已访问标志
#define _E_PAGE_DIRTY    (1 << 9)   // EPT已修改标志
#define _E_PAGE_USER     (1 << 10)  // EPT用户模式执行权限（Intel仅）

/// 可修改的EPT位掩码——Intel EPT的可修改位（包括bit51用于特殊用途）
/// AMD的NPT使用与常规PTE相同的权限位格式
#if VENDOR_ID == VENDOR_INTEL_ // Intel
#define MODIFIABLE_EPTE_BITS                                                                       \
    (_E_PAGE_PRESENT | _E_PAGE_RW | _E_PAGE_X | _E_PAGE_ACCESSED | _E_PAGE_DIRTY | _E_PAGE_USER |  \
     (1ULL << 51))
#else
#define MODIFIABLE_EPTE_BITS MODIFIABLE_PTE_BITS
#endif

// -------------------------------------------------------------------------------------------------
// 常规页表(x86_64四级页表)
// -------------------------------------------------------------------------------------------------
/// PML4级页表偏移——虚拟地址中PML4索引的位移量
#define PML4_SHIFT     39
/// PDPT级页表偏移——虚拟地址中PDPT索引的位移量
#define PDPT_SHIFT     30
/// PD级页表偏移——虚拟地址中PD索引的位移量
#define PDT_SHIFT      21
/// PT级页表偏移——虚拟地址中PT索引的位移量
#define PT_SHIFT       12
/// 最大虚拟地址位数——x86_64目前支持48位虚拟地址（ canonical address）
#define MAX_VADDR_BITS 48

/// 从虚拟地址提取PML4索引（9位，索引0-511）
#define PML4_INDEX(vaddr) (((uint64_t)(vaddr) >> PML4_SHIFT) & 0x1FF)
/// 从虚拟地址提取PDPT索引（9位）
#define PDPT_INDEX(vaddr) (((uint64_t)(vaddr) >> PDPT_SHIFT) & 0x1FF)
/// 从虚拟地址提取PD索引（9位）
#define PDT_INDEX(vaddr)  (((uint64_t)(vaddr) >> PDT_SHIFT) & 0x1FF)
/// 从虚拟地址提取PT索引（9位）
#define PT_INDEX(vaddr)   (((uint64_t)(vaddr) >> PT_SHIFT) & 0x1FF)

/// PML4E结构体——页映射级别4条目（对应Intel SDM Table 4-15）
/// 指向下一级PDPT页表的物理地址
/// bit域说明：
///   - present[0]: 存在位——为1表示该条目有效
///   - write_access[1]: 写权限位
///   - user_supervisor[2]: 用户/超级用户位——为1允许Ring3访问
///   - page_write_through[3]: 直写模式位
///   - page_cache_disable[4]: 缓存禁用位
///   - accessed[5]: 已访问位——CPU访问后自动设置
///   - paddr[12..PHYSICAL_WIDTH-1]: 下一级页表页的物理地址
///   - execute_disable[63]: 执行禁用位——为1禁止从此地址执行代码
typedef struct {
    uint64_t present : 1;               // 存在位——条目是否有效
    uint64_t write_access : 1;          // 写权限位
    uint64_t user_supervisor : 1;       // 用户/超级用户位——控制Ring3访问
    uint64_t page_write_through : 1;    // 直写模式位
    uint64_t page_cache_disable : 1;    // 缓存禁用位
    uint64_t accessed : 1;              // 已访问位
    uint64_t ignored : 1;               // 忽略位
    uint64_t reserved_zero : 1;         // 保留零位（必须为0）
    uint64_t ignored_11_8 : 4;          // 忽略位[11:8]
    uint64_t paddr : (PHYSICAL_WIDTH - 12); // 下一级页表物理地址
#if PHYSICAL_WIDTH < 52
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH); // 保留位[51:PHYSICAL_WIDTH]
#endif
    uint64_t ignored_62_52 : 11;        // 忽略位[62:52]
    uint64_t execute_disable : 1;       // 执行禁用位——禁止代码执行
} __attribute__((packed)) pml4e_t;

/// PDPTE结构体——页目录指针表条目（对应Intel SDM Table 4-17）
/// 指向下一级PD页表的物理地址
typedef struct {
    uint64_t present : 1;               // 存在位
    uint64_t write_access : 1;          // 写权限位
    uint64_t user_supervisor : 1;       // 用户/超级用户位
    uint64_t page_write_through : 1;    // 直写模式位
    uint64_t page_cache_disable : 1;    // 缓存禁用位
    uint64_t accessed : 1;              // 已访问位
    uint64_t ignored : 1;               // 忽略位
    uint64_t reserved_zero : 1;         // 保留零位
    uint64_t ignored_11_8 : 4;          // 忽略位[11:8]
    uint64_t paddr : (PHYSICAL_WIDTH - 12); // 下一级页表物理地址
#if PHYSICAL_WIDTH < 52
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH);
#endif
    uint64_t ignored_62_52 : 11;
    uint64_t execute_disable : 1;       // 执行禁用位
} __attribute__((packed)) pdpte_t;

/// PDTE结构体——页目录条目（对应Intel SDM Table 4-19）
/// 指向下一级PT页表的物理地址
typedef struct {
    uint64_t present : 1;               // 存在位
    uint64_t write_access : 1;          // 写权限位
    uint64_t user_supervisor : 1;       // 用户/超级用户位
    uint64_t page_write_through : 1;    // 直写模式位
    uint64_t page_cache_disable : 1;    // 缓存禁用位
    uint64_t accessed : 1;              // 已访问位
    uint64_t ignored : 1;               // 忽略位
    uint64_t reserved_zero : 1;         // 保留零位
    uint64_t ignored_11_8 : 4;          // 忽略位[11:8]
    uint64_t paddr : (PHYSICAL_WIDTH - 12); // 下一级页表物理地址
#if PHYSICAL_WIDTH < 52
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH);
#endif
    uint64_t ignored_62_52 : 11;
    uint64_t execute_disable : 1;       // 执行禁用位
} __attribute__((packed)) pdte_t;

/// PTE结构体——页表条目（对应Intel SDM Table 4-20）
/// 指向4KB物理页的地址，是最底层的页表条目
/// 使用pte_t_而非pte_t，因为linux/types.h已定义了pte_t
/// bit域说明：
///   - dirty[6]: 已修改位——CPU写入后自动设置
///   - page_attribute_table[7]: PAT位——选择页的缓存属性
///   - global_page[8]: 全局页位——TLB不因CR3切换而冲刷此页
///   - protection_key[59:62]: 保护键——控制页的额外访问权限(PKey)
typedef struct {
    uint64_t present : 1;               // 存在位
    uint64_t write_access : 1;          // 写权限位
    uint64_t user_supervisor : 1;       // 用户/超级用户位——侧信道测试的关键控制位
    uint64_t page_write_through : 1;    // 直写模式位
    uint64_t page_cache_disable : 1;    // 缓存禁用位
    uint64_t accessed : 1;              // 已访问位
    uint64_t dirty : 1;                 // 已修改位
    uint64_t page_attribute_table : 1;  // PAT位——缓存属性选择
    uint64_t global_page : 1;           // 全局页位
    uint64_t ignored_11_9 : 3;          // 忽略位[11:9]
    uint64_t paddr : (PHYSICAL_WIDTH - 12); // 4KB物理页地址
#if PHYSICAL_WIDTH < 52
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH);
#endif
    uint64_t ignored_58_52 : 7;
    uint64_t protection_key : 4;        // 保护键——PKey权限控制
    uint64_t execute_disable : 1;       // 执行禁用位
} __attribute__((packed)) pte_t_; // 使用pte_t_因为pte_t已在linux/types.h中定义

// -------------------------------------------------------------------------------------------------
// 扩展页表(EPT)——Intel VMX虚拟化的嵌套页表
// -------------------------------------------------------------------------------------------------

/// EPTP结构体——EPT页表指针（对应Intel SDM Figure 29-1）
/// 指向EPT根页表(PML4)的物理地址，存储在VMCS的EPT_POINTER字段中
/// bit域说明：
///   - memory_type[0:2]: EPT内存类型（0=WB, 1=WT, 4=UC, 5=WC, 6=WP）
///   - page_walk_length[3:5]: EPT层级数-1（典型值3=四级EPT）
///   - ad_enabled[6]: 访问/修改位启用——为1时EPT自动设置A/D位
///   - superv_sdw_stack[7]: 超级用户影子栈控制
///   - paddr[12:PHYSICAL_WIDTH-1]: EPT根页表物理地址
typedef struct {
    uint64_t memory_type : 3;           // EPT内存类型（WB/WT/UC等）
    uint64_t page_walk_length : 3;      // EPT层级数-1（3=四级EPT）
    uint64_t ad_enabled : 1;            // 访问/修改位启用
    uint64_t superv_sdw_stack : 1;      // 超级用户影子栈控制
    uint64_t reserved_11_08 : 4;        // 保留位[11:8]
    uint64_t paddr : (PHYSICAL_WIDTH - 12); // EPT根页表物理地址
#if PHYSICAL_WIDTH < 52
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH);
#endif
    uint64_t reserved_63_52 : 12;       // 保留位[63:52]
} __attribute__((packed)) eptp_t;

/// Intel EPT PML4E结构体（对应Intel SDM Table 28-1）
/// 权限位使用Read/Write/Execute而非Present/RW/User
/// 增加了user_ex_access位——控制用户模式（Ring3）下的执行权限
#if VENDOR_ID == 1 // Intel
typedef struct {
    uint64_t read_access : 1;           // 读访问权限
    uint64_t write_access : 1;          // 写访问权限
    uint64_t execute_access : 1;        // 执行访问权限
    uint64_t reserved_7_3 : 5;          // 保留位[7:3]
    uint64_t accessed : 1;              // 已访问位
    uint64_t ignored_9 : 1;             // 忽略位9
    uint64_t user_ex_access : 1;        // 用户模式执行访问权限
    uint64_t ignored_11 : 1;            // 忽略位11
    uint64_t paddr : (PHYSICAL_WIDTH - 12); // 下一级EPT页表物理地址
#if PHYSICAL_WIDTH < 52
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH);
#endif
    uint64_t ignored_63_52 : 12;
} __attribute__((packed)) epml4e_t;
#else
typedef pml4e_t epml4e_t;  // AMD NPT使用与常规PTE相同的格式
#endif

/// Intel EPT PDPTE结构体（对应Intel SDM Table 28-3）
#if VENDOR_ID == 1 // Intel
typedef struct {
    uint64_t read_access : 1;           // 读访问权限
    uint64_t write_access : 1;          // 写访问权限
    uint64_t execute_access : 1;        // 执行访问权限
    uint64_t reserved_6_3 : 4;          // 保留位[6:3]
    uint64_t reserved_7 : 1;            // 保留位7
    uint64_t accessed : 1;              // 已访问位
    uint64_t ignored_9 : 1;             // 忽略位9
    uint64_t user_ex_access : 1;        // 用户模式执行访问权限
    uint64_t ignored_11 : 1;            // 忽略位11
    uint64_t paddr : (PHYSICAL_WIDTH - 12); // 下一级EPT页表物理地址
#if PHYSICAL_WIDTH < 52
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH);
#endif
    uint64_t ignored_63_52 : 12;
} __attribute__((packed)) epdpte_t;
#else
typedef pdpte_t epdpte_t;
#endif

/// Intel EPT PDTE结构体
#if VENDOR_ID == 1 // Intel
typedef struct {
    uint64_t read_access : 1;           // 读访问权限
    uint64_t write_access : 1;          // 写访问权限
    uint64_t execute_access : 1;        // 执行访问权限
    uint64_t reserved_6_3 : 4;          // 保留位[6:3]
    uint64_t reserved_7 : 1;            // 保留位7
    uint64_t accessed : 1;              // 已访问位
    uint64_t ignored_9 : 1;             // 忽略位9
    uint64_t user_ex_access : 1;        // 用户模式执行访问权限
    uint64_t ignored_11 : 1;            // 忽略位11
    uint64_t paddr : (PHYSICAL_WIDTH - 12); // 下一级EPT页表物理地址
#if PHYSICAL_WIDTH < 52
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH);
#endif
    uint64_t ignored_63_52 : 12;
} __attribute__((packed)) epdte_t;
#else
typedef pdte_t epdte_t;
#endif

/// Intel EPT PTE结构体——最底层的EPT条目，指向4KB物理页
/// bit域说明：
///   - ept_mem_type[3:5]: EPT内存类型——控制Guest页的缓存属性
///   - ignore_pat[6]: 忽略PAT位——为1时使用EPT内存类型而非Guest PAT
///   - user_ex_access[10]: 用户模式执行访问——Ring3下的执行权限
///   - suppress_ve[63]: 抑制EPT虚拟化异常——控制#VE的触发
#if VENDOR_ID == 1 // Intel
typedef struct {
    uint64_t read_access : 1;           // 读访问权限——为0时Guest读取触发EPT违规
    uint64_t write_access : 1;          // 写访问权限——为0时Guest写入触发EPT违规
    uint64_t execute_access : 1;        // 执行访问权限——为0时Guest执行触发EPT违规
    uint64_t ept_mem_type : 3;          // EPT内存类型（WB/WT/UC等）
    uint64_t ignore_pat : 1;            // 忽略Guest PAT位
    uint64_t ignored_7 : 1;             // 忽略位7
    uint64_t accessed : 1;              // 已访问位
    uint64_t dirty : 1;                 // 已修改位
    uint64_t user_ex_access : 1;        // 用户模式执行访问权限
    uint64_t ignored_11 : 1;            // 忽略位11
    uint64_t paddr : (PHYSICAL_WIDTH - 12); // 4KB物理页地址
#if PHYSICAL_WIDTH < 52
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH);
#endif
    uint64_t ignored_56_52 : 5;
    uint64_t verif_guest_pag : 1;       // 验证Guest页位
    uint64_t pag_write_access : 1;      // 子页写权限位
    uint64_t ignored_59 : 1;            // 忽略位59
    uint64_t superv_sdw_stack : 1;      // 超级用户影子栈位
    uint64_t subpg_write_perm : 1;      // 子页写权限启用位
    uint64_t ignored_62 : 1;            // 忽略位62
    uint64_t suppress_ve : 1;           // 抑制EPT虚拟化异常(#VE)位
} __attribute__((packed)) epte_t_;
#else
typedef pte_t_ epte_t_;  // AMD NPT PTE使用与常规PTE相同的格式
#endif

/// 设置PTE的User位——使页可在Ring3(用户态)访问
/// 侧信道测试中用于：将faulty_area设置为用户可访问，
/// 测试代码可在Ring3下读取本应受保护的数据
static inline void set_user_bit(pte_t_ *pte) { pte->user_supervisor = 1; }

// =================================================================================================
// ARM64架构页表定义
// =================================================================================================
#elif defined(ARCH_ARM)

/// ARM64页表描述符格式——基于ARMv8-A VMSAv8-64架构参考手册D8.3.1
/// 所有定义基于4KB页（granule size = 4KB）
///
/// 可修改的PTE位掩码——ARM64中仅修改Valid, User, ReadOnly位
#define MODIFIABLE_PTE_BITS (PTE_VALID | PTE_USER | PTE_RDONLY)

/// L1描述符结构体——ARM64第一级页表条目（表描述符）
/// 指向下一级(L2)页表页
/// bit域说明：
///   - valid[0]: 有效位——为1表示描述符有效
///   - type[1]: 描述符类型——为1表示表描述符，为0表示块描述符
///   - nlta[9:47]: 下一级表地址——指向L2页表页的物理地址
///   - pxn_table[59]: 特权执行永不表位——禁止特权级执行
///   - uxn_table[60]: 用户执行永不表位——禁止用户级执行
///   - ap_table[61:62]: 访问权限表位——控制下层页的默认访问权限
///   - ns_table[63]: 非安全表位——控制下层页的安全属性
typedef struct {
    uint64_t valid : 1;                 // 有效位
    uint64_t type : 1;                  // 描述符类型（1=表描述符）
    uint64_t ignored_2_7 : 6;           // 忽略位[2:7]
    uint64_t nlta_high : 2;             // 下一级表地址高位[9:8]
    uint64_t access_flag : 1;           // 访问标志位
    uint64_t ignored_11 : 1;            // 忽略位11
    uint64_t nlta_low : 38;             // 下一级表地址低位[47:12]
    uint64_t reserved_50 : 1;           // 保留位50
    uint64_t ignored_51_58 : 8;         // 忽略位[51:58]
    uint64_t pxn_table : 1;             // 特权执行永不位——禁止特权级执行
    uint64_t uxn_table : 1;             // 用户执行永不位——禁止用户级执行
    uint64_t ap_table : 2;              // 访问权限表位——控制默认访问权限
    uint64_t ns_table : 1;              // 非安全表位
} __attribute__((packed)) l1_descr_t;

/// L2描述符结构体——ARM64第二级页表条目（表描述符）
/// 指向下一级(L3)页表页
typedef struct {
    uint64_t valid : 1;                 // 有效位
    uint64_t type : 1;                  // 描述符类型（1=表描述符）
    uint64_t ignored_2_7 : 6;           // 忽略位[2:7]
    uint64_t nlta_high : 2;             // 下一级表地址高位
    uint64_t access_flag : 1;           // 访问标志位
    uint64_t ignored_11 : 1;            // 忽略位11
    uint64_t nlta_low : 38;             // 下一级表地址低位
    uint64_t reserved_50 : 1;           // 保留位50
    uint64_t ignored_51_58 : 8;         // 忽略位[51:58]
    uint64_t reserved_59_63 : 5;        // 保留位[59:63]
} __attribute__((packed)) l2_descr_t;

/// L3描述符结构体——ARM64第三级页表条目（页描述符）
/// 指向4KB物理页——最底层的页表条目
/// bit域说明：
///   - attr_index[4:2]: 内存属性索引——选择MAIR_EL0中定义的属性
///   - non_secure[5]: 非安全位——标记页的安全属性
///   - access_permissions[6:7]: 访问权限——控制读/写/特权访问
///   - shareability[8:9]: 共享属性——控制缓存一致性（0=NSH, 2=OSH, 3=ISH）
///   - privileged_execute_never[53]: PXN位——禁止特权级执行
///   - execute_never[54]: XN位——禁止所有级别执行
typedef struct {
    uint64_t valid : 1;                 // 有效位
    uint64_t type : 1;                  // 描述符类型（1=页描述符）
    uint64_t attr_index : 3;            // 内存属性索引——选择MAIR中的属性
    uint64_t non_secure : 1;            // 非安全位
    uint64_t access_permissions : 2;    // 访问权限——读/写/特权控制
    uint64_t shareability : 2;          // 共享属性——缓存一致性控制
    uint64_t access_flag : 1;           // 访问标志位
    uint64_t not_global : 1;            // 非全局位——为1时TLB随ASID切换
    uint64_t paddr : 38;                // 4KB物理页地址
    uint64_t guarded : 1;               // guarded位——分支预测保护
    uint64_t dirty : 1;                 // 已修改位
    uint64_t contiguous : 1;            // 连续位——标记连续页块
    uint64_t privileged_execute_never : 1; // PXN位——禁止特权级执行
    uint64_t execute_never : 1;         // XN位——禁止所有级别执行
    uint64_t reserved_58_55 : 4;        // 保留位[58:55]
    uint64_t ignored_63_59 : 5;         // 忽略位[63:59]
} __attribute__((packed)) l3_descr_t;

/// 设置PTE的User位——ARM64版本的实现（目前为TODO）
static inline void set_user_bit(l3_descr_t *pte)
{
    // pte->user_supervisor = 1;  // TODO: ARM64的User位设置需进一步实现
}

/// ARM64页表条目类型别名——使用L3描述符作为最底层PTE类型
typedef l3_descr_t pte_t_;

#endif // ARCH_X86_64

#endif // _PAGE_TABLES_COMMON_H_
