/// File:
///  - Guest page table management
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

// 【客户机页表管理总体架构】
// 本文件实现了"Enter, Exit, Page Fault, Leak"论文Section 5.2中描述的客户机(Guest)页表管理功能。
//
// 在硬件虚拟化(VMX/SVM)环境下，内存映射涉及两层页表：
//   1. 客户机页表(Guest PT): 客户机虚拟地址(GVA) -> 客户机物理地址(GPA)
//      结构与常规x86_64页表相同：L4(PML4) -> L3(PDPT) -> L2(PD) -> L1(PT)
//   2. 扩展页表(EPT/NPT): 客户机物理地址(GPA) -> 宿主机物理地址(HPA)
//      Intel称为EPT，AMD称为NPT；结构为4级：L4 -> L3 -> L2 -> L1
//
// 本文件的核心功能：
//   - set_guest_page_tables(): 创建客户机4级页表，将GVA映射到GPA
//     - 支持HPA-GPA碰撞功能：将客户机数据页面的GPA直接映射到宿主机沙箱的HPA，
//       使宿主机和客户机访问同一物理内存（内存别名），这是侧信道fuzzer的关键特性
//   - set_extended_page_tables(): 创建EPT，将GPA映射到HPA
//     - 将宿主机沙箱内存映射到客户机地址空间
//   - update_eptp(): 配置EPTP(EPT指针)寄存器值，包含EPT基址、内存类型、遍历深度等
//   - set_faulty_page_guest_permissions(): 修改客户机页表中faulty页面的权限
//   - set_faulty_page_ept_permissions(): 修改EPT中faulty页面的权限
//   - restore_faulty_page_*_permissions(): 恢复faulty页面的原始权限
//
// 4级客户机页表结构(x86_64)：
//   L4(PML4E): 512个条目，索引[47:39]，指向L3页表
//   L3(PDPTE): 512个条目，索引[38:30]，指向L2页表  
//   L2(PDE):   512个条目，索引[29:21]，指向L1页表
//   L1(PTE):   512个条目，索引[20:12]，指向4KB物理页

#include <asm/io.h>
#include <asm/msr.h>

#include "actor.h"
#include "hardware_desc.h"
#include "main.h"
#include "sandbox_manager.h"
#include "shortcuts.h"

#include "page_tables_common.h"
#include "page_tables_guest.h"

// 【PTE/EPT初始化宏定义】
// INIT_PTE: 初始化客户机页表条目，设置权限位(Present/Write/User/WriteThrough/CacheDisable/XD/Accessed)
//           和物理地址(paddr >> 12，因为PTE中物理地址是页帧号而非完整地址)
// INIT_EPTE: 初始化扩展页表条目，Intel和AMD的EPT格式不同：
//   - Intel EPT: 权限位为Read/Write/Execute，无XD位(使用独立的execute_access位)
//   - AMD NPT: 权限位为Present/Write/User/WriteThrough/CacheDisable/XD(与传统PTE类似)
// INIT_PTE_DEFAULT: 默认PTE配置 — Present=1, Write=1, User=0(仅内核可访问), XD=0(可执行)
// INIT_EPTE_DEFAULT: 默认EPT配置 — Read=1, Write=1, Execute=1(完全可访问)
#define INIT_PTE(PTE, PADDR, P, W, US, PWT, PCD, XD, A)                                            \
    {                                                                                              \
        (PTE).present = P;                                                                         \
        (PTE).write_access = W;                                                                    \
        (PTE).user_supervisor = US;                                                                \
        (PTE).page_write_through = PWT;                                                            \
        (PTE).page_cache_disable = PCD;                                                            \
        (PTE).paddr = (PADDR) >> 12;                                                               \
        (PTE).execute_disable = XD;                                                                \
        (PTE).accessed = A;                                                                        \
    }

#if VENDOR_ID == VENDOR_INTEL_
#define INIT_EPTE(PTE, PADDR, P, W, X, A)                                                          \
    {                                                                                              \
        (PTE).read_access = P;                                                                     \
        (PTE).write_access = W;                                                                    \
        (PTE).execute_access = X;                                                                  \
        (PTE).paddr = (PADDR) >> 12;                                                               \
        (PTE).accessed = A;                                                                        \
    }
#else // AMD
#define INIT_EPTE(PTE, PADDR, P, W, X, A)                                                          \
    {                                                                                              \
        (PTE).present = P;                                                                         \
        (PTE).write_access = W;                                                                    \
        (PTE).user_supervisor = 1;                                                                 \
        (PTE).page_write_through = 0;                                                              \
        (PTE).page_cache_disable = 0;                                                              \
        (PTE).paddr = (PADDR) >> 12;                                                               \
        (PTE).execute_disable = X ^ 1;                                                             \
        (PTE).accessed = A;                                                                        \
    }
#endif

// 【EPT条目判断宏】不同CPU厂商的EPT格式差异：
// Intel: 存在性由read_access位决定，可执行性由execute_access位决定，用户访问性由user_ex_access位决定
// AMD: 存在性由present位决定，可执行性由execute_disable位(取反)决定，用户访问性由user_supervisor位决定
#define INIT_PTE_DEFAULT(PTE, PADDR)  INIT_PTE(PTE, PADDR, 1, 1, 0, 0, 0, 0, 1)
#define INIT_EPTE_DEFAULT(PTE, PADDR) INIT_EPTE(PTE, PADDR, 1, 1, 1, 1)

#if VENDOR_ID == VENDOR_INTEL_
#define EPTE_IS_PRESENT(EPT) EPT.read_access
#else
#define EPTE_IS_PRESENT(EPT) EPT.present
#endif

#if VENDOR_ID == VENDOR_INTEL_
#define EPTE_IS_EXECUTABLE(EPT) EPT.execute_access
#else
#define EPTE_IS_EXECUTABLE(EPT) (EPT.execute_disable ^ 1)
#endif

#if VENDOR_ID == VENDOR_INTEL_
#define EPTE_IS_USER_ACCESSIBLE(EPT) EPT.user_ex_access
#else
#define EPTE_IS_USER_ACCESSIBLE(EPT) EPT.user_supervisor
#endif

eptp_t *ept_ptr = NULL; // global
// 【全局数据结构】
// allocated_page_tables: 每个actor的客户机4级页表(L4/L3/L2/L1)
// allocated_extended_page_tables: 每个actor的EPT/NPT(L4/L3/L2/L1)
// allocated_guest_gdts: 每个actor的GDT(全局描述符表)，用于客户机段描述符配置
// guest_memory_translations: GVA->GPA->HPA->HVA的快速翻译表，加速地址转换查找
// vmlaunch_page: 包含单条VMCALL指令的页面，用于将VM置为已启动状态
// faulty_ptes/faulty_eptes: 保存faulty页面的原始PTE/EPT值，用于快速恢复

static actor_page_table_t *allocated_page_tables = NULL;
static actor_ept_t *allocated_extended_page_tables = NULL;
static actor_gdt_t *allocated_guest_gdts = NULL;
static guest_memory_translations_t *guest_memory_translations = NULL;
static uint8_t *vmlaunch_page = NULL;
static pte_t_ *faulty_ptes = NULL;
static epte_t_ *faulty_eptes = NULL;

static bool guest_pt_is_set = false;
static bool ept_is_set = false;

// =================================================================================================
// Helper functions
// =================================================================================================
/// @brief Translate a host physical address to a virtual address in high memory.
/// Note: This function is necessary because kernel does not provide a direct interface to search
/// for a physical address in page tables (or at least I couldn't find one)
/// @param hpa Host physical address to translate
/// @return Host virtual address in high memory
// 【phys_to_vmalloc - HPA到HVA转换】
// 作用：根据宿主机物理地址(HPA)查找对应的宿主机虚拟地址(HVA)。
// 为什么需要？内核没有提供根据物理地址搜索页表的接口，因此需要使用预先建立的
// guest_memory_translations翻译表进行查找。
// 实现：遍历翻译表中的所有hgpa_t条目，匹配hpa字段，返回对应的hva。
static void *phys_to_vmalloc(uint64_t hpa, int actor_id)
{
    hgpa_t *flat_translations = (hgpa_t *)&guest_memory_translations[actor_id];
    for (int i = 0; i < sizeof(guest_memory_translations_t) / sizeof(hgpa_t); i++) {
        if (flat_translations[i].hpa == hpa) {
            return flat_translations[i].hva;
        }
    }
    return 0;
}

static inline bool gpa_is_valid(hgpa_t *translations, uint64_t gpa)
{
    // 【gpa_is_valid - GPA有效性验证】
    // 作用：检查给定的客户机物理地址(GPA)是否在翻译表中存在有效映射。
    // 用途：在EPT调试输出中，当启用HPA-GPA碰撞时，同一个HPA可能映射到多个GPA，
    //       需要过滤掉未使用的GPA映射，只输出有效映射。
    for (int i = 0; i < sizeof(guest_memory_translations_t) / sizeof(hgpa_t); i++) {
        if (translations[i].gpa == gpa) {
            return true;
        }
    }
    return false;
}

static inline int set_last_pt_level(pte_t_ *pt, hgpa_t *translation, uint64_t paddr, uint64_t vaddr)
{
    // 【set_last_pt_level - 设置客户机页表L1(PTE)级别条目】
    // 作用：在客户机页表的最后一级(L1/PTE)中设置映射条目，将GVA映射到GPA。
    // 这是4级页表遍历的最后一步，直接映射4KB页面。
    // 同时更新翻译表：记录GPA和GVA的对应关系，供后续EPT设置和地址查找使用。
    size_t pt_index = PT_INDEX(vaddr);
    ASSERT(pt[pt_index].present == 0, "set_last_pt_level");
    INIT_PTE_DEFAULT(pt[pt_index], paddr);
    pt[pt_index].dirty = 1;

    translation->gpa = paddr;
    translation->gva = (void *)vaddr;
    return 0;
}

static inline int set_ept_entry(actor_ept_t *actor_ept_base, hgpa_t *translation, uint64_t l3_hpa,
                                uint64_t l2_hpa, uint64_t l1_hpa, void *hva)
{
    // 【set_ept_entry - 设置EPT映射条目】
    // 作用：在EPT的所有4个级别中设置映射，将GPA(客户机物理地址)转换为HPA(宿主机物理地址)。
    // EPT 4级结构：L4(EPML4E) -> L3(EPDPTE) -> L2(EPDE) -> L1(EPTE)
    // 
    // 输入参数：
    //   - actor_ept_base: 当前actor的EPT结构（包含L4/L3/L2/L1四个页表）
    //   - translation: 翻译条目，记录GPA->HPA->HVA的映射关系
    //   - l3_hpa/l2_hpa/l1_hpa: EPT中间级页表的宿主机物理地址
    //   - hva: 要映射的宿主机虚拟地址，通过vmalloc_to_phys转换为HPA
    //
    // 映射过程：
    //   1. 从translation->gpa获取客户机物理地址(GPA)
    //   2. 通过vmalloc_to_phys将HVA转换为HPA
    //   3. 检查EPT L1条目是否未被占用（避免碰撞）
    //   4. 设置EPT的4个级别：L4/L3/L2使用GPA对应位段作为索引，指向下一级EPT页表
    //   5. L1(叶级)使用GPA的[20:12]位作为索引，映射到HPA
    //   6. 设置L1的特殊属性：dirty=1(脏页标记)、内存类型(WB=6)、忽略PAT(Intel)或PAT=1(AMD)
    uint64_t gpa = translation->gpa;
    uint64_t hpa = vmalloc_to_phys(hva);

    // check for collisions
    // (the way we allocate page could, with very low likelihood, cause a collision)
    ASSERT(actor_ept_base->l1[PT_INDEX(gpa)].paddr == 0, "set_extended_page_tables");
    ASSERT(hpa, "set_extended_page_tables");

    translation->hpa = hpa;
    translation->hva = hva;

    // set all page table levels
    INIT_EPTE_DEFAULT(actor_ept_base->l4[PML4_INDEX(gpa)], l3_hpa);
    INIT_EPTE_DEFAULT(actor_ept_base->l3[PDPT_INDEX(gpa)], l2_hpa);
    INIT_EPTE_DEFAULT(actor_ept_base->l2[PDT_INDEX(gpa)], l1_hpa);
    INIT_EPTE_DEFAULT(actor_ept_base->l1[PT_INDEX(gpa)], hpa);

    // set additional properties for the last level
    actor_ept_base->l1[PT_INDEX(gpa)].dirty = 1;

#if VENDOR_ID == VENDOR_INTEL_
    actor_ept_base->l1[PT_INDEX(gpa)].ept_mem_type = 6;
    actor_ept_base->l1[PT_INDEX(gpa)].ignore_pat = 1;
#else
    actor_ept_base->l1[PT_INDEX(gpa)].page_attribute_table = 1;
#endif

    return 0;
}

// =================================================================================================
// Page table management interface
// =================================================================================================

/// @brief Set the guest page tables for all guest actors according to the layout defined in
/// guest_memory_t (see guest_page_tables.h), with the base address GUEST_MEMORY_START
/// @param void
/// @return 0 on success, -1 on failure
// 【set_guest_page_tables - 创建客户机4级页表】
// 作用：为每个客户机(Guest)actor创建4级页表，将GVA(客户机虚拟地址)映射到GPA(客户机物理地址)。
//
// 客户机页表的4级结构：
//   L4(PML4): 只使用一个条目(PML4_INDEX(GUEST_V_MEMORY_START))，指向L3页表
//   L3(PDPT): 只使用一个条目(PDPT_INDEX(GUEST_V_MEMORY_START))，指向L2页表
//   L2(PD):   只使用一个条目(PDT_INDEX(GUEST_V_MEMORY_START))，指向L1页表
//   L1(PT):   使用多个条目，分别映射util/data/code/gdt/vmlaunch等区域
//
// 关键设计：
//   - L4/L3/L2只使用一个条目，因为沙箱内存区域很小，所有地址共享同一组上级页表条目
//   - GPA的设置方式：为方便管理，客户机页表本身的GPA设为与GVA相同值（自映射式布局）
//   - HPA-GPA碰撞功能：当enable_hpa_gpa_collisions启用时，data/code区域的GPA
//     直接指向宿主机沙箱的HPA(vmalloc_to_phys)，实现内存别名，使宿主机和客户机
//     访问同一物理内存页面，这是侧信道攻击的基础条件
//
// 映射的区域（每个区域逐页映射）：
//   1. util_t: 工具页面（测量结果存储），所有actor共享
//   2. actor_data_t: 数据页面，每个actor独立（支持HPA-GPA碰撞）
//   3. actor_code_t: 代码页面，每个actor独立（支持HPA-GPA碰撞）
//   4. GDT: 全局描述符表，每个actor独立
//   5. VMLAUNCH页面: 包含VMCALL指令的特殊页面
static int set_guest_page_tables(void)
{
    int err = 0;
    uint64_t vaddr = 0;
    uint64_t paddr = 0;

    static size_t old_n_actors = 0;
    if (n_actors > old_n_actors) {
        SAFE_FREE(faulty_ptes);
        SAFE_FREE(faulty_eptes);
        faulty_ptes = (pte_t_ *)CHECKED_ZALLOC(sizeof(pte_t_) * n_actors);
        faulty_eptes = (epte_t_ *)CHECKED_ZALLOC(sizeof(epte_t_) * n_actors);
    }
    old_n_actors = n_actors;

    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // skip non-guest actors
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST) {
            continue;
        }

        // get a type that represents the guest memory
        guest_memory_t *guest_v_memory = (guest_memory_t *)(GUEST_V_MEMORY_START);
        guest_memory_t *guest_p_memory = (guest_memory_t *)(GUEST_P_MEMORY_START);
        guest_memory_translations_t *translations = &guest_memory_translations[actor_id];

        // Set the first three levels of the page table
        // For convenience, we set GPA of the page tables to the same value as their GVA
        // Also, since the actor's sandbox is fairly small, the first three levels are identical
        // for all addresses within the actor memory
        // 【设置L4/L3/L2级别】由于沙箱内存区域较小，所有地址共享相同的前三级页表条目。
        // 采用"GPA=GVA"的映射策略，使页表自身的物理地址与虚拟地址相同，简化地址管理。
        // 翻译表guest_page_tables[3..0]分别记录L4/L3/L2/L1页表的GPA。
        actor_page_table_t *page_table = &allocated_page_tables[actor_id];
        actor_page_table_t *page_table_gpa = &guest_p_memory->guest_page_tables;
        translations->guest_page_tables[3].gpa = (uint64_t)&page_table_gpa->l4;

        size_t l4_index = PML4_INDEX(GUEST_V_MEMORY_START);
        uint64_t l3_gpa = (uint64_t)&page_table_gpa->l3;
        INIT_PTE_DEFAULT(page_table->l4[l4_index], l3_gpa);
        translations->guest_page_tables[2].gpa = l3_gpa;

        size_t l3_index = PDPT_INDEX(GUEST_V_MEMORY_START);
        uint64_t l2_gpa = (uint64_t)&page_table_gpa->l2;
        INIT_PTE_DEFAULT(page_table->l3[l3_index], l2_gpa);
        translations->guest_page_tables[1].gpa = l2_gpa;

        size_t l2_index = PDT_INDEX(GUEST_V_MEMORY_START);
        uint64_t l1_gpa = (uint64_t)&page_table_gpa->l1;
        INIT_PTE_DEFAULT(page_table->l2[l2_index], l1_gpa);
        translations->guest_page_tables[0].gpa = l1_gpa;

        // set the last level of the page table for each area of the actor sandbox
        // 【设置L1(PTE)级别 - 各区域的逐页映射】
        // 以下逐页设置L1级别的PTE条目，将每个4KB页面映射到对应的GPA
        
        // util区域：所有actor共享，GPA直接指向客户机物理内存中的util区域
        for (int i = 0; i < sizeof(util_t); i += 4096) {
            vaddr = ((uint64_t)&guest_v_memory->util) + i;
            paddr = ((uint64_t)&guest_p_memory->util) + i;
            err = set_last_pt_level(page_table->l1, &translations->util[i / 4096], paddr, vaddr);
            CHECK_ERR("set_guest_page_tables");
        }
        for (int i = 0; i < sizeof(actor_data_t); i += 4096) {
            // 【HPA-GPA碰撞（内存别名）功能】
            // 当enable_hpa_gpa_collisions启用时，客户机数据页面的GPA不指向客户机物理内存，
            // 而直接指向宿主机沙箱(sandbox->data[0])对应的HPA(vmalloc_to_phys转换)。
            // 这使得客户机和宿主机访问同一物理内存页面，形成内存别名(alias)。
            // 作用：宿主机actor(在Ring 0执行)和客户机actor(在VM中执行)共享同一数据页面，
            //       客户机修改的数据可以直接被宿主机读取，反之亦然。这是跨VM侧信道通信的基础。
            // 注意：data区域使用sandbox->data[0]（第一个actor的数据页面）作为别名目标，
            //       因为所有actor的data页面在沙箱中是连续分配的。
            uint64_t vaddr = ((uint64_t)&guest_v_memory->data) + i;
            if (enable_hpa_gpa_collisions) {
                uint64_t aliased_vaddr = ((uint64_t)&sandbox->data[0]) + i;
                paddr = vmalloc_to_phys((void *)aliased_vaddr);
            } else {
                paddr = ((uint64_t)&guest_p_memory->data) + i;
            }
            err = set_last_pt_level(page_table->l1, &translations->data[i / 4096], paddr, vaddr);
            CHECK_ERR("set_guest_page_tables");
        }
        for (int i = 0; i < sizeof(actor_code_t); i += 4096) {
            // 【代码区域的HPA-GPA碰撞】与data区域同理，code区域也支持HPA-GPA碰撞功能，
            // 使宿主机和客户机共享同一代码页面。
            vaddr = ((uint64_t)&guest_v_memory->code) + i;
            if (enable_hpa_gpa_collisions) {
                uint64_t aliased_vaddr = ((uint64_t)&sandbox->code[0]) + i;
                paddr = vmalloc_to_phys((void *)aliased_vaddr);
            } else {
                paddr = ((uint64_t)&guest_p_memory->code) + i;
            }
            err = set_last_pt_level(page_table->l1, &translations->code[i / 4096], paddr, vaddr);
            CHECK_ERR("set_guest_page_tables");
        }
        { // GDT (indentation is for readability)
            // 【GDT映射】全局描述符表(GDT)映射到客户机物理内存，每个actor有独立的GDT
            vaddr = (uint64_t)&guest_v_memory->gdt;
            paddr = (uint64_t)&guest_p_memory->gdt;
            err = set_last_pt_level(page_table->l1, &translations->gdt[0], paddr, vaddr);
            CHECK_ERR("set_guest_page_tables");
        }
        { // VMLAUNCH page (indentation is for readability)
            // 【VMLAUNCH页面】包含VMCALL指令(0x0f 0x01 0xc1)的特殊页面，
            // 用于将VM从VMLAUNCH状态转为运行状态
            vaddr = (uint64_t)&guest_v_memory->vmlaunch_page[0];
            paddr = (uint64_t)&guest_p_memory->vmlaunch_page[0];
            err = set_last_pt_level(page_table->l1, &translations->vmlaunch_page[0], paddr, vaddr);
            CHECK_ERR("set_guest_page_tables");
        }
    }

    guest_pt_is_set = true;
    return 0;
}

/// @brief Map sandbox_t from host memory into the guest memory of each guest actor, according to
/// the layout defined in guest_memory_t (see page_tables_guest.h), with the base address equal to
/// GUEST_MEMORY_START
/// @param void
/// @return 0 on success, -1 on failure
// 【set_extended_page_tables - 创建EPT映射】
// 作用：为每个客户机actor创建扩展页表(EPT/NPT)，将GPA映射到HPA。
// EPT是硬件虚拟化的第二层地址转换：GVA -> GPA（由客户机PT完成） -> HPA（由EPT完成）
//
// EPT映射流程：
//   1. 获取当前actor的EPT结构和翻译表
//   2. 获取EPT中间级(L3/L2/L1)页表的HPA（通过vmalloc_to_phys转换虚拟地址）
//   3. 对每个内存区域逐页调用set_ept_entry()，设置4级EPT映射
//
// 映射区域：
//   - util_t: 共享的工具页面，所有actor映射同一宿主机物理内存(sandbox->util)
//   - actor_data_t: 每个actor独立的数据页面(sandbox->data[actor_id])
//   - actor_code_t: 每个actor独立的代码页面(sandbox->code[actor_id])
//   - GDT: 每个actor独立的GDT(allocated_guest_gdts[actor_id])
//   - VMLAUNCH页面: 共享的VMCALL指令页面
//   - 客户机页表自身: 逐页映射allocated_page_tables到EPT中，使客户机可以访问自己的页表
//
// 前置条件：guest_pt_is_set必须为true（客户机页表已设置），因为EPT需要使用翻译表中的GPA
static int set_extended_page_tables(void)
{
    int err = 0;

    ASSERT(actors != NULL, "set_extended_page_tables");
    ASSERT(sandbox != NULL, "set_extended_page_tables");
    ASSERT(guest_pt_is_set, "set_extended_page_tables");

    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // skip non-guest actors
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST) {
            continue;
        }
        actor_ept_t *ept_base = &allocated_extended_page_tables[actor_id];
        guest_memory_translations_t *translations = &guest_memory_translations[actor_id];

        // get addresses of the last three levels
        // 【获取EPT中间级页表的HPA】EPT中间级(L3/L2/L1)页表存储在vmalloc分配的内存中，
        // 需要将其虚拟地址转换为物理地址(HPA)，作为EPT条目中的下一级页表指针。
        uint64_t l3_hpa = vmalloc_to_phys((void *)ept_base->l3);
        uint64_t l2_hpa = vmalloc_to_phys((void *)ept_base->l2);
        uint64_t l1_hpa = vmalloc_to_phys((void *)ept_base->l1);

        // map util_t into guest memory (the same phys range for all actors, i.e., shared)
        // 【util区域EPT映射】所有actor共享同一个util区域(sandbox->util[0])，
        // 映射到同一个宿主机物理地址范围
        for (int i = 0; i < sizeof(util_t) / PAGE_SIZE; i += 1) {
            void *hva = (void *)&sandbox->util[0] + (i * PAGE_SIZE);
            err = set_ept_entry(ept_base, &translations->util[i], l3_hpa, l2_hpa, l1_hpa, hva);
            CHECK_ERR("set_extended_page_tables");
        }

        // map actor_data_t, actor_code_t, and GDT into guest memory (each actor has its own)
        // 【actor独占区域EPT映射】data/code/GDT每个actor有自己独立的映射，
        // 使用sandbox->data[actor_id]等获取对应actor的宿主机虚拟地址
        for (int i = 0; i < sizeof(actor_data_t) / PAGE_SIZE; i += 1) {
            void *hva = (void *)&sandbox->data[actor_id] + (i * PAGE_SIZE);
            err = set_ept_entry(ept_base, &translations->data[i], l3_hpa, l2_hpa, l1_hpa, hva);
            CHECK_ERR("set_extended_page_tables");
        }
        for (int i = 0; i < sizeof(actor_code_t) / PAGE_SIZE; i += 1) {
            void *hva = (void *)&sandbox->code[actor_id] + (i * PAGE_SIZE);
            err = set_ept_entry(ept_base, &translations->code[i], l3_hpa, l2_hpa, l1_hpa, hva);
            CHECK_ERR("set_extended_page_tables");
        }
        { // indent for readability
            void *hva = (void *)&allocated_guest_gdts[actor_id];
            err = set_ept_entry(ept_base, &translations->gdt[0], l3_hpa, l2_hpa, l1_hpa, hva);
            CHECK_ERR("set_extended_page_tables");
        }
        { // indent for readability
            void *hva = (void *)&vmlaunch_page[0];
            err = set_ept_entry(ept_base, &translations->vmlaunch_page[0], l3_hpa, l2_hpa, l1_hpa,
                                hva);
            CHECK_ERR("set_extended_page_tables");
        }

        // map guest page tables
        // 【客户机页表自身的EPT映射】客户机页表也需要映射到EPT中，
        // 因为客户机在运行时需要通过GVA访问自己的页表结构（如修改PTE权限时）。
        // 逐页映射allocated_page_tables[actor_id]到EPT的GPA空间。
        for (int i = 0; i < sizeof(actor_page_table_t) / PAGE_SIZE; i += 1) {
            void *hva = (void *)&allocated_page_tables[actor_id] + (i * PAGE_SIZE);
            err = set_ept_entry(ept_base, &translations->guest_page_tables[i], l3_hpa, l2_hpa,
                                l1_hpa, hva);
            CHECK_ERR("set_extended_page_tables");
        }
    }

    ept_is_set = true;
    return 0;
}

/// @brief Store a pointer to the EPT of actor 1 (default) in ept_ptr after updating extended page
/// tables
/// @param void
/// @return 0 on success, -1 on failure
// 【update_eptp - 更新EPT指针】
// 作用：为每个actor配置EPTP(EPT Pointer)寄存器值，VMX的VMLAUNCH/VMENTRY指令使用
// EPTP来定位EPT的基址和属性。
// EPTP结构(x86_64)：
//   - memory_type: EPT内存类型，WB(WriteBack=6)是最高性能的缓存模式
//   - page_walk_length: EPT遍历深度，3表示4级EPT(L4->L3->L2->L1，长度=4-1=3)
//   - ad_enabled: 访问位和脏位(A/D bits)启用，用于跟踪页面访问和修改状态
//   - superv_sdw_stack: Supervisor Shadow Stack控制位(通常为0)
//   - paddr: EPT L4页表的物理地址(页帧号格式，地址>>12)
static int update_eptp(void)
{
    ASSERT(ept_is_set, "update_eptp");
    SAFE_FREE(ept_ptr);
    ept_ptr = CHECKED_ZALLOC(sizeof(eptp_t) * n_actors);
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        actor_ept_t *actor_ept_base = &allocated_extended_page_tables[actor_id];
        ept_ptr[actor_id].memory_type = VMX_BASIC_MEM_TYPE_WB;
        ept_ptr[actor_id].page_walk_length = 3;
        ept_ptr[actor_id].ad_enabled = 1; // native_read_msr(MSR_IA32_VMX_EPT_VPID_CAP) &0x00200000;
        ept_ptr[actor_id].superv_sdw_stack = 0;
        ept_ptr[actor_id].paddr = vmalloc_to_phys(actor_ept_base->l4) >> 12;
    }

    return 0;
}

int map_sandbox_to_guest_memory(void)
{
    // 【沙箱到客户机内存映射的主入口】
    // 执行流程：1. 设置客户机页表(GVA->GPA) -> 2. 设置EPT(GPA->HPA) -> 3. 更新EPT指针
    // 必须按此顺序执行，因为EPT设置依赖客户机页表中建立的翻译表(GPA值)。
    int err = 0;
    ASSERT(allocated_page_tables != NULL, "map_sandbox_to_guest_memory");
    ASSERT(allocated_extended_page_tables != NULL, "map_sandbox_to_guest_memory");
    ASSERT(allocated_guest_gdts != NULL, "map_sandbox_to_guest_memory");

    err = set_guest_page_tables();
    CHECK_ERR("set_guest_page_tables");

    err = set_extended_page_tables();
    CHECK_ERR("set_extended_page_tables");

    err = update_eptp();
    CHECK_ERR("update_eptp");

    return 0;
}

/// @brief Set permissions on the faulty page based on the actor's metadata (for each actor)
/// @param void
// 【set_faulty_page_guest_permissions - 设置客户机PT中faulty页面的权限】
// 作用：在客户机页表的L1级别修改faulty数据页面的PTE权限位。
// 实现方式：与宿主机版本(set_faulty_page_host_permissions)类似，
//   1. 计算faulty页面的GVA，通过PT_INDEX获取L1表中的索引
//   2. 从actor->data_permissions提取权限掩码(mask_set/mask_clear)
//   3. 保存原始PTE到faulty_ptes[]，用于后续恢复
//   4. 应用权限掩码：pte = (org_pte | mask_set) & mask_clear
// 注意：客户机PT修改不需要TLB刷新，因为客户机TLB在VM Entry/Exit时自动刷新
void set_faulty_page_guest_permissions(void)
{
    guest_memory_t *guest_v_memory = (guest_memory_t *)(GUEST_V_MEMORY_START);
    uint64_t vaddr = ((uint64_t)&guest_v_memory->data.faulty_area[0]);
    size_t index = PT_INDEX(vaddr);

    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST)
            continue;

        uint64_t pte_mask = actor->data_permissions;
        uint64_t mask_set = pte_mask & MODIFIABLE_PTE_BITS;
        uint64_t mask_clear = pte_mask | ~MODIFIABLE_PTE_BITS;

        pte_t_ *ptep = &allocated_page_tables[actor_id].l1[index];
        faulty_ptes[actor_id] = *ptep;

        uint64_t org_pte = *(uint64_t *)ptep;
        uint64_t pte = (org_pte | mask_set) & mask_clear;
        if (pte != org_pte) {
            *(uint64_t *)ptep = pte;
            // native_page_invalidate(vaddr);
        }
    }
}

void restore_faulty_page_guest_permissions(void)
{
    // 【restore_faulty_page_guest_permissions - 恢复客户机PT中faulty页面的权限】
    // 作用：将每个客户机actor的faulty页面PTE恢复为set_faulty_page_guest_permissions()
    // 执行前保存的原始值(faulty_ptes[actor_id])。
    guest_memory_t *guest_v_memory = (guest_memory_t *)(GUEST_V_MEMORY_START);
    uint64_t vaddr = ((uint64_t)&guest_v_memory->data.faulty_area[0]);
    size_t index = PT_INDEX(vaddr);

    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST)
            continue;

        allocated_page_tables[actor_id].l1[index] = faulty_ptes[actor_id];
    }
}

/// @brief Set EPT permissions on the faulty page based on the actor's metadata (for each actor)
/// @param void
// 【set_faulty_page_ept_permissions - 设置EPT中faulty页面的权限】
// 作用：在EPT的L1级别修改faulty数据页面的EPT权限位。
// 与客户机PT版本的区别：
//   - 使用actor->data_ept_properties而非data_permissions（EPT和PT的权限位格式不同）
//   - 使用MODIFIABLE_EPTE_BITS而非MODIFIABLE_PTE_BITS（EPT可修改的位集合不同）
//   - EPT权限位含义：Intel(Read/Write/Execute)，AMD(Present/Write/XD)
//   - GPA通过翻译表(translations->data[FAULTY_PAGE_ID].gpa)获取，而非直接计算
// 实现方式与PT版本类似：保存原始EPT值 -> 应用掩码 -> 仅在改变时写入
void set_faulty_page_ept_permissions(void)
{
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST)
            continue;

        guest_memory_translations_t *translations = &guest_memory_translations[actor_id];
        uint64_t gpa = translations->data[FAULTY_PAGE_ID].gpa;
        size_t index = PT_INDEX(gpa);

        uint64_t pte_mask = actor->data_ept_properties;
        uint64_t mask_set = pte_mask & MODIFIABLE_EPTE_BITS;
        uint64_t mask_clear = pte_mask | ~MODIFIABLE_EPTE_BITS;

        epte_t_ *ptep = &allocated_extended_page_tables[actor_id].l1[index];
        faulty_eptes[actor_id] = *ptep;

        uint64_t org_pte = *(uint64_t *)ptep;
        uint64_t pte = (org_pte | mask_set) & mask_clear;
        if (pte != org_pte) {
            *(uint64_t *)ptep = pte;
            // native_page_invalidate(vaddr);
        }
    }
}

void restore_faulty_page_ept_permissions(void)
{
    // 【restore_faulty_page_ept_permissions - 恢复EPT中faulty页面的权限】
    // 作用：将每个客户机actor的faulty页面EPT条目恢复为原始值(faulty_eptes[actor_id])。
    // 与客户机PT恢复类似，使用预先保存的值直接覆盖EPT的L1条目。
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST)
            continue;

        guest_memory_translations_t *translations = &guest_memory_translations[actor_id];
        uint64_t gpa = translations->data[FAULTY_PAGE_ID].gpa;
        size_t index = PT_INDEX(gpa);

        allocated_extended_page_tables[actor_id].l1[index] = faulty_eptes[actor_id];
    }
}

// =================================================================================================
// Debugging Interfaces
// =================================================================================================

/// @brief Dump the guest page tables for a given actor
/// @param actor_id
/// @return 0 on success, -1 on failure
int dbg_dump_guest_page_tables(int actor_id)
{
    // NOTE: the implementation below traverses page tables as if they were unbounded (i.e.,
    //   contained an unlimited number of PTEs, PDs, etc). This is not the case for the guest page
    //   tables as we have only one PT per actor. However, this implementation is more future-proof,
    //   so we have a traditional page walk, and just check the number of entries with asserts
    printk(KERN_INFO "------- Page table dump for actor %d ---------------\n", actor_id);
    actor_page_table_t *page_table = &allocated_page_tables[actor_id];
    guest_memory_translations_t *translations = &guest_memory_translations[actor_id];

    // L4 traversal
    pml4e_t *l4 = page_table->l4;
    for (uint64_t curr_l4_id = 0; curr_l4_id < ENTRIES_PER_PAGE; curr_l4_id += 1) {
        pml4e_t l4e = l4[curr_l4_id]; // current L4 entry
        if (!l4e.present)
            continue;
        // we allocate memory such that only the first L4 entry is used
        ASSERT(curr_l4_id == 0, "dbg_dump_guest_page_tables");

        uint64_t l3_gpa = ((uint64_t)l4e.paddr << 12);
        ASSERT_MSG(l3_gpa == translations->guest_page_tables[2].gpa, "dbg_dump_guest_page_tables",
                   "0x%llx != 0x%llx\n", l3_gpa, translations->guest_page_tables[2].gpa);
        pdpte_t *l3 = (pdpte_t *)translations->guest_page_tables[2].hva;

        // L3 traversal
        for (uint64_t curr_l3_id = 0; curr_l3_id < ENTRIES_PER_PAGE; curr_l3_id += 1) {
            pdpte_t l3e = l3[curr_l3_id]; // current L3 entry
            if (!l3e.present)
                continue;
            // we allocate memory such that only the first L3 entry is used
            ASSERT(curr_l3_id == 0, "dbg_dump_guest_page_tables");

            uint64_t l2_gpa = ((uint64_t)l3e.paddr << 12);
            ASSERT(l2_gpa == translations->guest_page_tables[1].gpa, "dbg_dump_guest_page_tables");
            pdte_t *l2 = (pdte_t *)translations->guest_page_tables[1].hva;

            // L2 traversal
            for (uint64_t curr_l2_id = 0; curr_l2_id < ENTRIES_PER_PAGE; curr_l2_id += 1) {
                pdte_t l2e = l2[curr_l2_id]; // current L2 entry
                if (!l2e.present)
                    continue;
                ASSERT(curr_l2_id == 0, "dbg_dump_guest_page_tables");

                uint64_t l1_gpa = ((uint64_t)l2e.paddr << 12);
                ASSERT(l1_gpa == translations->guest_page_tables[0].gpa,
                       "dbg_dump_guest_page_tables");
                pte_t_ *l1 = (pte_t_ *)translations->guest_page_tables[0].hva;

                // L1 traversal
                for (uint64_t curr_l1_id = 0; curr_l1_id < ENTRIES_PER_PAGE; curr_l1_id += 1) {
                    pte_t_ l1e = l1[curr_l1_id];
                    if (!l1e.present)
                        continue;
                    uint64_t paddr = ((uint64_t)l1e.paddr << 12);
                    uint64_t vaddr = (curr_l4_id << PML4_SHIFT) | (curr_l3_id << PDPT_SHIFT) |
                                     (curr_l2_id << PDT_SHIFT) | (curr_l1_id << PT_SHIFT);
                    char p = l1e.present ? 'P' : '-';
                    char w = l1e.write_access ? 'W' : '-';
                    char us = l1e.user_supervisor ? 'U' : '-';
                    char pwt = l1e.page_write_through ? 'T' : '-';
                    char pcd = l1e.page_cache_disable ? 'C' : '-';
                    char a = l1e.accessed ? 'A' : '-';
                    char d = l1e.dirty ? 'D' : '-';
                    char pat = l1e.page_attribute_table ? 'T' : '-';
                    char g = l1e.global_page ? 'G' : '-';
                    char x = l1e.execute_disable ? '-' : 'X';
                    printk(KERN_INFO "V: 0x%-16llx -> P: 0x%-16llx; %c%c%c%c%c%c%c%c%c%c\n", vaddr,
                           paddr, p, w, us, pwt, pcd, a, d, pat, g, x);
                }
            }
        }
    }
    return 0;
}

int dbg_dump_ept(int actor_id)
{
    printk(KERN_INFO "------- EPT dump -----------------------------------\n");
    actor_ept_t *actor_ept_base = &allocated_extended_page_tables[actor_id];

    // L4 traversal
    epml4e_t *l4 = actor_ept_base->l4;
    for (uint64_t curr_l4_id = 0; curr_l4_id < ENTRIES_PER_PAGE; curr_l4_id += 1) {
        epml4e_t l4e = l4[curr_l4_id];
        if (!EPTE_IS_PRESENT(l4e))
            continue;
        uint64_t l3_hpa = ((uint64_t)l4e.paddr << 12);
        epdpte_t *l3 = actor_ept_base->l3;
        ASSERT((l3_hpa & ~0xFFF) == vmalloc_to_phys(l3), "dbg_dump_ept");

        // L3 traversal
        for (uint64_t curr_l3_id = 0; curr_l3_id < ENTRIES_PER_PAGE; curr_l3_id += 1) {
            epdpte_t l3e = l3[curr_l3_id];
            if (!EPTE_IS_PRESENT(l3e))
                continue;
            uint64_t l2_hpa = ((uint64_t)l3e.paddr << 12);
            epdte_t *l2 = actor_ept_base->l2;
            ASSERT((l2_hpa & ~0xFFF) == vmalloc_to_phys(l2), "dbg_dump_ept");

            // L2 traversal
            for (uint64_t curr_l2_id = 0; curr_l2_id < ENTRIES_PER_PAGE; curr_l2_id += 1) {
                epdte_t l2e = l2[curr_l2_id];
                if (!EPTE_IS_PRESENT(l2e))
                    continue;
                uint64_t l1_hpa = ((uint64_t)l2e.paddr << 12);
                epte_t_ *l1 = actor_ept_base->l1;
                ASSERT((l1_hpa & ~0xFFF) == vmalloc_to_phys(l1), "dbg_dump_ept");

                // L1 traversal
                for (uint64_t curr_l1_id = 0; curr_l1_id < ENTRIES_PER_PAGE; curr_l1_id += 1) {
                    epte_t_ l1e = l1[curr_l1_id];
                    if (!EPTE_IS_PRESENT(l1e))
                        continue;
                    uint64_t gpa = (curr_l4_id << PML4_SHIFT) | (curr_l3_id << PDPT_SHIFT) |
                                   (curr_l2_id << PDT_SHIFT) | (curr_l1_id << PT_SHIFT);

                    // if HPA-GPA collisions are enabled, we will have multiple translations per
                    // physical address; hence, filter out the unused GPAs
                    if (enable_hpa_gpa_collisions &&
                        !gpa_is_valid((hgpa_t *)&guest_memory_translations[actor_id], gpa)) {
                        continue;
                    }

                    uint64_t hpa = ((uint64_t)l1e.paddr << 12);
                    void *hva = phys_to_vmalloc(hpa, actor_id);
                    char r = EPTE_IS_PRESENT(l1e) ? 'R' : '-';
                    char w = l1e.write_access ? 'W' : '-';
                    char x = EPTE_IS_EXECUTABLE(l1e) ? 'X' : '-';
                    char a = l1e.accessed ? 'A' : '-';
                    char d = l1e.dirty ? 'D' : '-';
                    char us = EPTE_IS_USER_ACCESSIBLE(l1e) ? 'U' : '-';
                    printk(KERN_INFO
                           "GP: 0x%-16llx -> HP: 0x%-16llx (HV: 0x%-16llx); %c%c%c%c%c%c\n",
                           gpa, hpa, (uint64_t)hva, r, w, x, a, d, us);
                }
            }
        }
    }
    return 0;
}

// =================================================================================================
int allocate_guest_page_tables()
{
    // 【allocate_guest_page_tables - 分配客户机页表和EPT的内存】
    // 作用：为所有actor分配客户机页表(actor_page_table_t)、EPT(actor_ept_t)、
    //       GDT(actor_gdt_t)和翻译表(guest_memory_translations_t)的内存。
    // 
    // 内存分配策略：
    //   - 页表和EPT使用vmalloc分配（因为它们很大，kmalloc可能失败）
    //   - 翻译表和vmlaunch_page使用kmalloc分配（较小，需要物理连续内存）
    //   - 如果actor数量没有增加(n_actors <= old_n_actors)，仅清零现有内存而不重新分配
    //
    // vmlaunch_page的特殊处理：
    //   这是一个包含VMCALL指令(0x0f 0x01 0xc1)的4KB页面，
    //   用于在VMLAUNCH后通过VMCALL将VM置于已启动状态
    ASSERT(n_actors < 64, "allocate_guest_page_tables");

    static size_t old_n_actors = 0;
    if (n_actors <= old_n_actors) {
        memset(allocated_page_tables, 0, n_actors * sizeof(actor_page_table_t));
        memset(allocated_extended_page_tables, 0, n_actors * sizeof(actor_ept_t));
        memset(allocated_guest_gdts, 0, n_actors * sizeof(actor_gdt_t));
        memset(guest_memory_translations, 0, n_actors * sizeof(guest_memory_translations_t));
        return 0;
    }
    old_n_actors = n_actors;
    SAFE_VFREE(allocated_page_tables);
    SAFE_VFREE(allocated_extended_page_tables);
    SAFE_VFREE(allocated_guest_gdts);
    SAFE_FREE(guest_memory_translations);
    SAFE_FREE(vmlaunch_page);

    // Guest page tables
    // 【客户机4级页表】每个actor需要一套完整的4级页表(L4/L3/L2/L1)，
    // 结构actor_page_table_t包含这4个页表，每个页表4KB(512个8字节条目)
    allocated_page_tables =
        (actor_page_table_t *)CHECKED_VMALLOC(n_actors * sizeof(actor_page_table_t));
    memset(allocated_page_tables, 0, n_actors * sizeof(actor_page_table_t));

    // EPTs
    // 【扩展页表】每个actor需要一套完整的4级EPT(L4/L3/L2/L1)，
    // 结构actor_ept_t包含这4个EPT页表，每个页表4KB
    allocated_extended_page_tables = (actor_ept_t *)CHECKED_VMALLOC(n_actors * sizeof(actor_ept_t));
    memset(allocated_extended_page_tables, 0, n_actors * sizeof(actor_ept_t));

    allocated_guest_gdts = CHECKED_VMALLOC(n_actors * sizeof(actor_gdt_t));

    // Fast translations
    // 【快速翻译表】记录每个页面的GVA->GPA->HPA->HVA映射关系，
    // 用于加速地址转换和EPT设置中的HPA查找
    guest_memory_translations = CHECKED_ZALLOC(n_actors * sizeof(guest_memory_translations_t));

    // A page with a single VMCALL instruction; used to put the VM into launched state
    vmlaunch_page = CHECKED_ZALLOC(PAGE_SIZE);
    vmlaunch_page[0] = 0x0f;
    vmlaunch_page[1] = 0x01;
    vmlaunch_page[2] = 0xc1;

    faulty_ptes = (pte_t_ *)CHECKED_ZALLOC(sizeof(pte_t_));
    faulty_eptes = (epte_t_ *)CHECKED_ZALLOC(sizeof(epte_t_));

    guest_pt_is_set = false;
    ept_is_set = false;
    return 0;
}

void free_guest_page_tables(void)
{
    // 【释放客户机页表相关内存】安全释放所有分配的资源，包括页表、EPT、GDT、翻译表等。
    // 使用SAFE_VFREE释放vmalloc分配的内存，SAFE_FREE释放kmalloc分配的内存。
    SAFE_VFREE(allocated_page_tables);
    SAFE_VFREE(allocated_extended_page_tables);
    SAFE_VFREE(allocated_guest_gdts);
    SAFE_FREE(guest_memory_translations);
    SAFE_FREE(ept_ptr);
    SAFE_FREE(vmlaunch_page);
    SAFE_FREE(faulty_ptes);
    SAFE_FREE(faulty_eptes);
}
