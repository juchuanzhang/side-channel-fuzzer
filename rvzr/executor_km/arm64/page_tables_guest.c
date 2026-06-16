/// 文件：ARM64架构客户机页表管理
///
/// 本文件实现了ARM64架构下的客户机(Guest)页表管理功能，是x86版page_tables_guest.c的ARM64等价实现。
///
/// 【ARM64虚拟化地址翻译架构 vs x86虚拟化地址翻译架构】
/// 在x86硬件虚拟化环境下：
///   1. Guest PT: GVA→GPA（客户机页表）
///   2. EPT/NPT: GPA→HPA（扩展页表，Intel称EPT，AMD称NPT）
///
/// 在ARM64硬件虚拟化环境下（名称不同但概念等价）：
///   1. S1PT(Stage-1页表): GVA→IPA（IPA=中间物理地址，ARM64的GPA等价概念）
///      由客户机OS管理，TTBR0_EL1/TTBR1_EL1指向
///   2. S2PT(Stage-2页表): IPA→HPA（ARM64的EPT/NPT等价概念）
///      由Hypervisor管理，VTTBR_EL2指向
///
/// 【术语对照】x86 GPA ≈ ARM64 IPA；x86 EPT/NPT ≈ ARM64 S2PT；
///   x86 EPTP ≈ ARM64 VTTBR_EL2；x86 VMCALL ≈ ARM64 HVC；x86 GDT ≈ ARM64异常向量表
///
/// 【S2PT叶级描述符位布局（简化格式，与EPT R/W/X对齐）】
///   Bit[0]=Valid, Bit[1]=Read, Bit[2]=Write, Bit[3]=Exec, Bit[10]=AF(必须设1),
///   Bits[47:12]=Output Address, Bits[54:53]=Attr_hi, Bit[58]=AP2, Bit[59]=DBM,
///   Bit[60]=GP, Bit[61]=Attr3, Bit[62]=AP1, Bit[63]=SW reserved
///
/// 【S1PT描述符位布局（标准VMSAv8-64格式）】
///   Bit[0]=Valid, Bit[1]=Type(Page/Table), Bits[4:2]=AttrIndex, Bit[5]=NS,
///   Bits[7:6]=AP(00=RW@EL1,01=RW@EL01,10=RO@EL1,11=RO@EL01),
///   Bits[9:8]=SH(11=InnerShareable), Bit[10]=AF, Bit[11]=nG,
///   Bits[47:12]=Output Address, Bit[53]=PXN, Bit[54]=XN, Bit[59]=DBM
///
/// 【4级页表结构（4KB页粒度，48位PA，与x86位移值相同）】
///   L0(PGD)→L1(PUD)→L2(PMD)→L3(PTE)，每级512条目，9位索引
///
/// 【VTTBR_EL2格式】Bits[47:12]=BADDR(S2PT L0物理地址), Bits[63:48]=VMID(16位)
///
/// Copyright (C) Microsoft Corporation
/// SPDX-License-Identifier: MIT

#include "page_tables_guest.h"
#include "actor.h"
#include "main.h"
#include "sandbox_manager.h"
#include "shortcuts.h"
#include "page_tables_common.h"

// =================================================================================================
// S1PT/S2PT条目初始化宏（实现级辅助宏，仅在.c文件中使用）
// =================================================================================================

// INIT_S1_TABLE：初始化S1PT非叶级(Table)描述符，指向下一级页表IPA
#define INIT_S1_TABLE(ENTRY, NEXT_IPA)                                                                \
    {                                                                                                  \
        (ENTRY) = S1_TABLE_VALID | S1_TABLE_TYPE | S1_TABLE_AF | ((NEXT_IPA) & 0x0000FFFFFFFFF000ULL); \
    }

// INIT_S1_PTE：初始化S1PT叶级(Page)描述符，GVA→IPA，WB缓存+Inner共享+RW@EL1默认
#define INIT_S1_PTE(ENTRY, IPA, PERMS)                                                                \
    {                                                                                                  \
        (ENTRY) = S1_PTE_VALID | S1_PTE_PAGE | S1_ATTR_NORMAL_WB | S1_SH_ISH | S1_PTE_AF |           \
                  (PERMS) | ((IPA) & 0x0000FFFFFFFFF000ULL);                                           \
    }

// INIT_S2_TABLE：初始化S2PT非叶级(Table)描述符，指向下一级页表HPA
#define INIT_S2_TABLE(ENTRY, NEXT_HPA)                                                                \
    {                                                                                                  \
        (ENTRY) = S2_TABLE_VALID | S2_TABLE_TYPE | S2_TABLE_AF | ((NEXT_HPA) & 0x0000FFFFFFFFF000ULL); \
    }

// INIT_S2_PTE：初始化S2PT叶级(Page)描述符，IPA→HPA，R+W+X+AF默认权限
#define INIT_S2_PTE(ENTRY, HPA, PERMS)                                                                \
    {                                                                                                  \
        (ENTRY) = S2_PTE_VALID | S2_PTE_AF | (PERMS) | ((HPA) & 0x0000FFFFFFFFF000ULL);              \
    }

// 默认初始化：S1PT=Valid+RW@EL1(仅内核读写可执行); S2PT=Valid+R+W+X(完全可访问)
#define INIT_S1_PTE_DEFAULT(ENTRY, IPA)  INIT_S1_PTE(ENTRY, IPA, S1_AP_RW_EL1)
#define INIT_S2_PTE_DEFAULT(ENTRY, HPA)  INIT_S2_PTE(ENTRY, HPA, S2_PTE_READ | S2_PTE_WRITE | S2_PTE_EXEC)

// S2PT条目判断宏（等价于x86 EPTE_IS_PRESENT/IS_EXECUTABLE等）
#define S2_PTE_IS_PRESENT(EPT)   ((EPT) & S2_PTE_VALID)
#define S2_PTE_IS_READABLE(EPT)  ((EPT) & S2_PTE_READ)
#define S2_PTE_IS_WRITABLE(EPT)  ((EPT) & S2_PTE_WRITE)
#define S2_PTE_IS_EXECUTABLE(EPT) ((EPT) & S2_PTE_EXEC)

// =================================================================================================
// 全局数据结构
// =================================================================================================
// allocated_s1_page_tables: 每个actor的S1PT(Stage-1页表，GVA→IPA)，指针式4级结构
// allocated_s2_page_tables: 每个actor的S2PT(Stage-2页表，IPA→HPA)，等价于x86 EPT
// allocated_exception_vectors: 异常向量表(ARM64替代x86 GDT)
// guest_memory_translations: GVA→IPA→HPA→HVA快速翻译表
// hvc_page: HVC指令页面(ARM64替代x86 VMLAUNCH页)，HVC #0编码=0xD4000002
// s2pt_ptr: VTTBR_EL2寄存器值数组(BADDR+VMID)，等价于x86 ept_ptr
// faulty_s1_ptes/faulty_s2_ptes: 保存faulty页原始S1PT/S2PT条目值

s2ptp_t *s2pt_ptr = NULL;

static actor_s1_page_table_t *allocated_s1_page_tables = NULL;
static actor_s2_page_table_t *allocated_s2_page_tables = NULL;
static actor_exception_vectors_t *allocated_exception_vectors = NULL;
static guest_memory_translations_t *guest_memory_translations = NULL;
static uint8_t *hvc_page = NULL;
static uint64_t *faulty_s1_ptes = NULL;
static uint64_t *faulty_s2_ptes = NULL;

static bool guest_pt_is_set = false;
static bool s2pt_is_set = false;

// =================================================================================================
// 辅助函数
// =================================================================================================

// phys_to_vmalloc - HPA→HVA查找：遍历翻译表匹配hpa，返回hva
// 内核无HPA→HVA接口，需使用预先建立的翻译表
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

// gpa_is_valid - IPA有效性验证：过滤HPA-IPA碰撞中未使用的IPA映射
static inline bool gpa_is_valid(hgpa_t *translations, uint64_t gpa)
{
    for (int i = 0; i < sizeof(guest_memory_translations_t) / sizeof(hgpa_t); i++) {
        if (translations[i].gpa == gpa) {
            return true;
        }
    }
    return false;
}

// set_last_s1_pt_level - 设置S1PT L3(PTE)叶级条目，GVA→IPA映射
// 4级遍历最后一步，同时更新翻译表记录IPA和GVA对应关系
static inline int set_last_s1_pt_level(uint64_t *l3, hgpa_t *translation, uint64_t ipa,
                                        uint64_t gva)
{
    size_t pt_index = S1_L3_INDEX(gva);
    ASSERT(l3[pt_index] == 0, "set_last_s1_pt_level");
    INIT_S1_PTE_DEFAULT(l3[pt_index], ipa);
    translation->gpa = ipa;
    translation->gva = (void *)gva;
    return 0;
}

// set_s2_pt_entry - 设置S2PT 4级全映射，IPA→HPA
// L0/L1/L2设Table描述符指向下一级，L3设Page描述符映射HPA
// 等价于x86 set_ept_entry，但使用ARM64 S2PT描述符格式
static inline int set_s2_pt_entry(actor_s2_page_table_t *s2_pt, hgpa_t *translation, void *hva)
{
    uint64_t ipa = translation->gpa;
    uint64_t hpa = vmalloc_to_phys(hva);

    // 碰撞检查：S2PT L3条目未被占用
    ASSERT((s2_pt->l3[S2_L3_INDEX(ipa)] & S2_PTE_ADDR_MASK) == 0, "set_s2_pt_entry");
    ASSERT(hpa, "set_s2_pt_entry");

    translation->hpa = hpa;
    translation->hva = hva;

    // 获取S2PT中间级页表的HPA（vmalloc分配的页面）
    uint64_t l1_hpa = vmalloc_to_phys(s2_pt->l1);
    uint64_t l2_hpa = vmalloc_to_phys(s2_pt->l2);
    uint64_t l3_hpa = vmalloc_to_phys(s2_pt->l3);

    // 设置4级S2PT：L0→L1→L2→L3(叶级映射HPA，默认R+W+X权限)
    INIT_S2_TABLE(s2_pt->l0[S2_L0_INDEX(ipa)], l1_hpa);
    INIT_S2_TABLE(s2_pt->l1[S2_L1_INDEX(ipa)], l2_hpa);
    INIT_S2_TABLE(s2_pt->l2[S2_L2_INDEX(ipa)], l3_hpa);
    INIT_S2_PTE_DEFAULT(s2_pt->l3[S2_L3_INDEX(ipa)], hpa);

    return 0;
}

// =================================================================================================
// 页表管理接口
// =================================================================================================

// allocate_guest_page_tables - 为所有actor分配S1PT/S2PT页表内存
// 每个级别单独vmalloc分配4KB页面（指针式结构），便于获取物理地址
// hvc_page含HVC #0指令(0xD4000002)，等价于x86 vmlaunch_page的VMCALL
int allocate_guest_page_tables(void)
{
    ASSERT(n_actors < 64, "allocate_guest_page_tables");

    static size_t old_n_actors = 0;
    if (n_actors <= old_n_actors) {
        // actor数未增加时仅清零页表内容
        for (int i = 0; i < n_actors; i++) {
            memset(allocated_s1_page_tables[i].l0, 0, PAGE_SIZE);
            memset(allocated_s1_page_tables[i].l1, 0, PAGE_SIZE);
            memset(allocated_s1_page_tables[i].l2, 0, PAGE_SIZE);
            memset(allocated_s1_page_tables[i].l3, 0, PAGE_SIZE);
            memset(allocated_s2_page_tables[i].l0, 0, PAGE_SIZE);
            memset(allocated_s2_page_tables[i].l1, 0, PAGE_SIZE);
            memset(allocated_s2_page_tables[i].l2, 0, PAGE_SIZE);
            memset(allocated_s2_page_tables[i].l3, 0, PAGE_SIZE);
        }
        memset(allocated_exception_vectors, 0, n_actors * sizeof(actor_exception_vectors_t));
        memset(guest_memory_translations, 0, n_actors * sizeof(guest_memory_translations_t));
        return 0;
    }
    old_n_actors = n_actors;

    // actor数增加时重新分配所有资源
    SAFE_VFREE(allocated_s1_page_tables);
    SAFE_VFREE(allocated_s2_page_tables);
    SAFE_VFREE(allocated_exception_vectors);
    SAFE_FREE(guest_memory_translations);
    SAFE_FREE(s2pt_ptr);
    SAFE_FREE(hvc_page);
    SAFE_FREE(faulty_s1_ptes);
    SAFE_FREE(faulty_s2_ptes);

    // S1PT/S2PT结构体数组（每actor一个，包含4个指针）
    allocated_s1_page_tables =
        (actor_s1_page_table_t *)CHECKED_VMALLOC(n_actors * sizeof(actor_s1_page_table_t));
    memset(allocated_s1_page_tables, 0, n_actors * sizeof(actor_s1_page_table_t));

    allocated_s2_page_tables =
        (actor_s2_page_table_t *)CHECKED_VMALLOC(n_actors * sizeof(actor_s2_page_table_t));
    memset(allocated_s2_page_tables, 0, n_actors * sizeof(actor_s2_page_table_t));

    // 异常向量表（ARM64替代x86 GDT）
    allocated_exception_vectors =
        CHECKED_VMALLOC(n_actors * sizeof(actor_exception_vectors_t));

    // 快速翻译表
    guest_memory_translations = CHECKED_ZALLOC(n_actors * sizeof(guest_memory_translations_t));

    // VTTBR_EL2指针数组
    s2pt_ptr = CHECKED_ZALLOC(sizeof(s2ptp_t) * n_actors);

    // HVC指令页面（ARM64 HVC #0 = 0xD4000002，小端序：02 00 00 D4）
    hvc_page = CHECKED_ZALLOC(PAGE_SIZE);
    hvc_page[0] = 0x02;
    hvc_page[1] = 0x00;
    hvc_page[2] = 0x00;
    hvc_page[3] = 0xD4;

    faulty_s1_ptes = (uint64_t *)CHECKED_ZALLOC(sizeof(uint64_t) * n_actors);
    faulty_s2_ptes = (uint64_t *)CHECKED_ZALLOC(sizeof(uint64_t) * n_actors);

    guest_pt_is_set = false;
    s2pt_is_set = false;

    // 为每个actor的S1PT/S2PT分配4个级别的页表页面
    for (int i = 0; i < n_actors; i++) {
        allocated_s1_page_tables[i].l0 = (uint64_t *)CHECKED_VMALLOC(PAGE_SIZE);
        allocated_s1_page_tables[i].l1 = (uint64_t *)CHECKED_VMALLOC(PAGE_SIZE);
        allocated_s1_page_tables[i].l2 = (uint64_t *)CHECKED_VMALLOC(PAGE_SIZE);
        allocated_s1_page_tables[i].l3 = (uint64_t *)CHECKED_VMALLOC(PAGE_SIZE);
        memset(allocated_s1_page_tables[i].l0, 0, PAGE_SIZE);
        memset(allocated_s1_page_tables[i].l1, 0, PAGE_SIZE);
        memset(allocated_s1_page_tables[i].l2, 0, PAGE_SIZE);
        memset(allocated_s1_page_tables[i].l3, 0, PAGE_SIZE);

        allocated_s2_page_tables[i].l0 = (uint64_t *)CHECKED_VMALLOC(PAGE_SIZE);
        allocated_s2_page_tables[i].l1 = (uint64_t *)CHECKED_VMALLOC(PAGE_SIZE);
        allocated_s2_page_tables[i].l2 = (uint64_t *)CHECKED_VMALLOC(PAGE_SIZE);
        allocated_s2_page_tables[i].l3 = (uint64_t *)CHECKED_VMALLOC(PAGE_SIZE);
        memset(allocated_s2_page_tables[i].l0, 0, PAGE_SIZE);
        memset(allocated_s2_page_tables[i].l1, 0, PAGE_SIZE);
        memset(allocated_s2_page_tables[i].l2, 0, PAGE_SIZE);
        memset(allocated_s2_page_tables[i].l3, 0, PAGE_SIZE);
    }

    return 0;
}

// set_guest_page_tables - 创建S1PT(Stage-1页表)，GVA→IPA
// 4级结构：L0(PGD)仅1条目→L1(PUD)仅1条目→L2(PMD)仅1条目→L3(PTE)多条目
// L0/L1/L2共享（沙箱区域小），L3逐页映射util/data/code/exception_vectors/hvc_page
// IPA策略：页表自身IPA=GVA布局偏移；HPA-IPA碰撞时data/code IPA指向sandbox HPA
static int set_guest_page_tables(void)
{
    int err = 0;
    uint64_t vaddr = 0;
    uint64_t paddr = 0;

    static size_t old_n_actors = 0;
    if (n_actors > old_n_actors) {
        SAFE_FREE(faulty_s1_ptes);
        SAFE_FREE(faulty_s2_ptes);
        faulty_s1_ptes = (uint64_t *)CHECKED_ZALLOC(sizeof(uint64_t) * n_actors);
        faulty_s2_ptes = (uint64_t *)CHECKED_ZALLOC(sizeof(uint64_t) * n_actors);
    }
    old_n_actors = n_actors;

    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST)
            continue;

        guest_memory_t *guest_v_memory = (guest_memory_t *)(GUEST_V_MEMORY_START);
        guest_memory_t *guest_p_memory = (guest_memory_t *)(GUEST_P_MEMORY_START);
        guest_memory_translations_t *translations = &guest_memory_translations[actor_id];
        actor_s1_page_table_t *s1_pt = &allocated_s1_page_tables[actor_id];

        // L0/L1/L2: 设置Table描述符指向下一级页表的IPA
        // 页表自身IPA采用自映射式布局（IPA=GVA布局中对应偏移）
        translations->s1_page_tables[3].gpa = (uint64_t)&guest_p_memory->s1_page_tables[3 * PAGE_SIZE];

        size_t l0_index = S1_L0_INDEX(GUEST_V_MEMORY_START);
        uint64_t l1_ipa = (uint64_t)&guest_p_memory->s1_page_tables[2 * PAGE_SIZE];
        INIT_S1_TABLE(s1_pt->l0[l0_index], l1_ipa);
        translations->s1_page_tables[2].gpa = l1_ipa;

        size_t l1_index = S1_L1_INDEX(GUEST_V_MEMORY_START);
        uint64_t l2_ipa = (uint64_t)&guest_p_memory->s1_page_tables[1 * PAGE_SIZE];
        INIT_S1_TABLE(s1_pt->l1[l1_index], l2_ipa);
        translations->s1_page_tables[1].gpa = l2_ipa;

        size_t l2_index = S1_L2_INDEX(GUEST_V_MEMORY_START);
        uint64_t l3_ipa = (uint64_t)&guest_p_memory->s1_page_tables[0];
        INIT_S1_TABLE(s1_pt->l2[l2_index], l3_ipa);
        translations->s1_page_tables[0].gpa = l3_ipa;

        // L3(PTE): 各区域逐页映射

        // util区域：所有actor共享，IPA指向客户机物理内存
        for (int i = 0; i < sizeof(util_t); i += 4096) {
            vaddr = ((uint64_t)&guest_v_memory->util) + i;
            paddr = ((uint64_t)&guest_p_memory->util) + i;
            err = set_last_s1_pt_level(s1_pt->l3, &translations->util[i / 4096], paddr, vaddr);
            CHECK_ERR("set_guest_page_tables");
        }

        // data区域：支持HPA-IPA碰撞（内存别名），使宿主机和客户机共享同一物理页面
        for (int i = 0; i < sizeof(actor_data_t); i += 4096) {
            uint64_t vaddr_data = ((uint64_t)&guest_v_memory->data) + i;
            if (enable_hpa_gpa_collisions) {
                uint64_t aliased_vaddr = ((uint64_t)&sandbox->data[0]) + i;
                paddr = vmalloc_to_phys((void *)aliased_vaddr);
            } else {
                paddr = ((uint64_t)&guest_p_memory->data) + i;
            }
            err = set_last_s1_pt_level(s1_pt->l3, &translations->data[i / 4096], paddr, vaddr_data);
            CHECK_ERR("set_guest_page_tables");
        }

        // code区域：与data同理，支持HPA-IPA碰撞
        for (int i = 0; i < sizeof(actor_code_t); i += 4096) {
            vaddr = ((uint64_t)&guest_v_memory->code) + i;
            if (enable_hpa_gpa_collisions) {
                uint64_t aliased_vaddr = ((uint64_t)&sandbox->code[0]) + i;
                paddr = vmalloc_to_phys((void *)aliased_vaddr);
            } else {
                paddr = ((uint64_t)&guest_p_memory->code) + i;
            }
            err = set_last_s1_pt_level(s1_pt->l3, &translations->code[i / 4096], paddr, vaddr);
            CHECK_ERR("set_guest_page_tables");
        }

        // 异常向量表（ARM64替代x86 GDT），每个actor独立
        {
            vaddr = (uint64_t)&guest_v_memory->exception_vectors[0];
            paddr = (uint64_t)&guest_p_memory->exception_vectors[0];
            err = set_last_s1_pt_level(s1_pt->l3, &translations->exception_vectors[0], paddr, vaddr);
            CHECK_ERR("set_guest_page_tables");
        }

        // HVC指令页面（ARM64替代x86 vmlaunch_page），包含HVC #0陷入指令
        {
            vaddr = (uint64_t)&guest_v_memory->hvc_page[0];
            paddr = (uint64_t)&guest_p_memory->hvc_page[0];
            err = set_last_s1_pt_level(s1_pt->l3, &translations->hvc_page[0], paddr, vaddr);
            CHECK_ERR("set_guest_page_tables");
        }
    }

    guest_pt_is_set = true;
    return 0;
}

// set_extended_page_tables - 创建S2PT(Stage-2页表)，IPA→HPA
// S2PT是ARM64的EPT/NPT等价概念，由VTTBR_EL2指向
// 映射区域：util(共享)/data(每actor)/code(每actor)/exception_vectors/hvc_page/S1PT自身
// 前置条件：guest_pt_is_set=true（S2PT依赖翻译表中IPA值）
static int set_extended_page_tables(void)
{
    int err = 0;

    ASSERT(actors != NULL, "set_extended_page_tables");
    ASSERT(sandbox != NULL, "set_extended_page_tables");
    ASSERT(guest_pt_is_set, "set_extended_page_tables");

    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST)
            continue;

        actor_s2_page_table_t *s2_pt = &allocated_s2_page_tables[actor_id];
        guest_memory_translations_t *translations = &guest_memory_translations[actor_id];

        // util: 共享，映射sandbox->util[0]
        for (int i = 0; i < sizeof(util_t) / PAGE_SIZE; i += 1) {
            void *hva = (void *)&sandbox->util[0] + (i * PAGE_SIZE);
            err = set_s2_pt_entry(s2_pt, &translations->util[i], hva);
            CHECK_ERR("set_extended_page_tables");
        }

        // data: 每actor独立，映射sandbox->data[actor_id]
        for (int i = 0; i < sizeof(actor_data_t) / PAGE_SIZE; i += 1) {
            void *hva = (void *)&sandbox->data[actor_id] + (i * PAGE_SIZE);
            err = set_s2_pt_entry(s2_pt, &translations->data[i], hva);
            CHECK_ERR("set_extended_page_tables");
        }

        // code: 每actor独立，映射sandbox->code[actor_id]
        for (int i = 0; i < sizeof(actor_code_t) / PAGE_SIZE; i += 1) {
            void *hva = (void *)&sandbox->code[actor_id] + (i * PAGE_SIZE);
            err = set_s2_pt_entry(s2_pt, &translations->code[i], hva);
            CHECK_ERR("set_extended_page_tables");
        }

        // exception_vectors: 每actor独立（ARM64替代x86 GDT）
        {
            void *hva = (void *)&allocated_exception_vectors[actor_id];
            err = set_s2_pt_entry(s2_pt, &translations->exception_vectors[0], hva);
            CHECK_ERR("set_extended_page_tables");
        }

        // hvc_page: 共享HVC指令页面（ARM64替代x86 vmlaunch_page）
        {
            void *hva = (void *)&hvc_page[0];
            err = set_s2_pt_entry(s2_pt, &translations->hvc_page[0], hva);
            CHECK_ERR("set_extended_page_tables");
        }

        // S1PT自身：客户机需要通过GVA访问自己的页表结构（如修改PTE权限）
        // 逐级映射4个S1PT页面到S2PT的IPA空间
        {
            void *hva = (void *)allocated_s1_page_tables[actor_id].l0;
            err = set_s2_pt_entry(s2_pt, &translations->s1_page_tables[3], hva);
            CHECK_ERR("set_extended_page_tables");
        }
        {
            void *hva = (void *)allocated_s1_page_tables[actor_id].l1;
            err = set_s2_pt_entry(s2_pt, &translations->s1_page_tables[2], hva);
            CHECK_ERR("set_extended_page_tables");
        }
        {
            void *hva = (void *)allocated_s1_page_tables[actor_id].l2;
            err = set_s2_pt_entry(s2_pt, &translations->s1_page_tables[1], hva);
            CHECK_ERR("set_extended_page_tables");
        }
        {
            void *hva = (void *)allocated_s1_page_tables[actor_id].l3;
            err = set_s2_pt_entry(s2_pt, &translations->s1_page_tables[0], hva);
            CHECK_ERR("set_extended_page_tables");
        }
    }

    s2pt_is_set = true;
    return 0;
}

// update_s2ptp - 创建VTTBR_EL2指针值（BADDR + VMID）
// VTTBR_EL2格式：Bits[47:12]=BADDR(S2PT L0物理地址), Bits[63:48]=VMID
// VMID用于TLB标签，避免不同VM间TLB冲突（等价于x86 VPID）
// x86 EPTP含memory_type/walk_length/ad等，ARM64 VTTBR_EL2仅含BADDR+VMID（更简洁）
static int update_s2ptp(void)
{
    ASSERT(s2pt_is_set, "update_s2ptp");
    SAFE_FREE(s2pt_ptr);
    s2pt_ptr = CHECKED_ZALLOC(sizeof(s2ptp_t) * n_actors);

    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        actor_s2_page_table_t *s2_pt = &allocated_s2_page_tables[actor_id];
        // BADDR = S2PT L0页面的HPA（掩码保留[47:12]位）
        // VMID = actor_id（左移至Bits[63:48]）
        uint64_t baddr = vmalloc_to_phys(s2_pt->l0) & 0x0000FFFFFFFFF000ULL;
        uint64_t vmid = (uint64_t)actor_id << 48;
        s2pt_ptr[actor_id].paddr = baddr | vmid;
    }

    return 0;
}

// map_sandbox_to_guest_memory - 沙箱到客户机内存映射主入口
// 流程：1.S1PT(GVA→IPA) → 2.S2PT(IPA→HPA) → 3.VTTBR_EL2指针
// 必须按此顺序（S2PT依赖S1PT翻译表中IPA值）
int map_sandbox_to_guest_memory(void)
{
    int err = 0;
    ASSERT(allocated_s1_page_tables != NULL, "map_sandbox_to_guest_memory");
    ASSERT(allocated_s2_page_tables != NULL, "map_sandbox_to_guest_memory");
    ASSERT(allocated_exception_vectors != NULL, "map_sandbox_to_guest_memory");

    err = set_guest_page_tables();
    CHECK_ERR("set_guest_page_tables");

    err = set_extended_page_tables();
    CHECK_ERR("set_extended_page_tables");

    err = update_s2ptp();
    CHECK_ERR("update_s2ptp");

    return 0;
}

// set_faulty_page_guest_permissions - 修改S1PT中faulty页面权限
// 在S1PT L3级别修改faulty数据页的权限位(AP/PXN/XN)
// 使用actor->data_permissions掩码，MODIFIABLE_S1_PTE_BITS限定可修改位范围
// 保存原始值到faulty_s1_ptes[]用于恢复
void set_faulty_page_guest_permissions(void)
{
    guest_memory_t *guest_v_memory = (guest_memory_t *)(GUEST_V_MEMORY_START);
    uint64_t vaddr = ((uint64_t)&guest_v_memory->data.faulty_area[0]);
    size_t index = S1_L3_INDEX(vaddr);

    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST)
            continue;

        uint64_t pte_mask = actor->data_permissions;
        uint64_t mask_set = pte_mask & MODIFIABLE_S1_PTE_BITS;
        uint64_t mask_clear = pte_mask | ~MODIFIABLE_S1_PTE_BITS;

        uint64_t *ptep = &allocated_s1_page_tables[actor_id].l3[index];
        faulty_s1_ptes[actor_id] = *ptep;

        uint64_t org_pte = *ptep;
        uint64_t pte = (org_pte | mask_set) & mask_clear;
        if (pte != org_pte) {
            *ptep = pte;
        }
    }
}

// restore_faulty_page_guest_permissions - 恢复S1PT faulty页面原始权限
void restore_faulty_page_guest_permissions(void)
{
    guest_memory_t *guest_v_memory = (guest_memory_t *)(GUEST_V_MEMORY_START);
    uint64_t vaddr = ((uint64_t)&guest_v_memory->data.faulty_area[0]);
    size_t index = S1_L3_INDEX(vaddr);

    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST)
            continue;

        allocated_s1_page_tables[actor_id].l3[index] = faulty_s1_ptes[actor_id];
    }
}

// set_faulty_page_ept_permissions - 修改S2PT中faulty页面权限
// ARM64的"EPT"即S2PT，修改L3级别的S2PT条目权限(Valid/Read/Write/Exec)
// 使用actor->data_ept_properties掩码，MODIFIABLE_S2_PTE_BITS限定可修改位
// IPA通过翻译表获取，保存原始值到faulty_s2_ptes[]
void set_faulty_page_ept_permissions(void)
{
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST)
            continue;

        guest_memory_translations_t *translations = &guest_memory_translations[actor_id];
        uint64_t ipa = translations->data[FAULTY_PAGE_ID].gpa;
        size_t index = S2_L3_INDEX(ipa);

        uint64_t pte_mask = actor->data_ept_properties;
        uint64_t mask_set = pte_mask & MODIFIABLE_S2_PTE_BITS;
        uint64_t mask_clear = pte_mask | ~MODIFIABLE_S2_PTE_BITS;

        uint64_t *ptep = &allocated_s2_page_tables[actor_id].l3[index];
        faulty_s2_ptes[actor_id] = *ptep;

        uint64_t org_pte = *ptep;
        uint64_t pte = (org_pte | mask_set) & mask_clear;
        if (pte != org_pte) {
            *ptep = pte;
        }
    }
}

// restore_faulty_page_ept_permissions - 恢复S2PT faulty页面原始权限
void restore_faulty_page_ept_permissions(void)
{
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST)
            continue;

        guest_memory_translations_t *translations = &guest_memory_translations[actor_id];
        uint64_t ipa = translations->data[FAULTY_PAGE_ID].gpa;
        size_t index = S2_L3_INDEX(ipa);

        allocated_s2_page_tables[actor_id].l3[index] = faulty_s2_ptes[actor_id];
    }
}

// =================================================================================================
// 调试接口
// =================================================================================================

// dbg_dump_guest_page_tables - 遍历并打印S1PT(客户机Stage-1页表)
// 打印每个有效L3条目的GVA→IPA映射和权限(V/R/W/U/X/P/A)
int dbg_dump_guest_page_tables(int actor_id)
{
    printk(KERN_INFO "------- S1PT(客户机Stage-1页表) dump for actor %d ---------------\n", actor_id);
    actor_s1_page_table_t *s1_pt = &allocated_s1_page_tables[actor_id];
    guest_memory_translations_t *translations = &guest_memory_translations[actor_id];

    uint64_t *l0 = s1_pt->l0;
    for (uint64_t curr_l0_id = 0; curr_l0_id < ENTRIES_PER_PAGE; curr_l0_id += 1) {
        uint64_t l0e = l0[curr_l0_id];
        if (!(l0e & S1_TABLE_VALID))
            continue;
        ASSERT(curr_l0_id == 0, "dbg_dump_guest_page_tables");

        uint64_t l1_ipa = l0e & 0x0000FFFFFFFFF000ULL;
        ASSERT_MSG(l1_ipa == translations->s1_page_tables[2].gpa, "dbg_dump_guest_page_tables",
                   "0x%llx != 0x%llx\n", l1_ipa, translations->s1_page_tables[2].gpa);
        uint64_t *l1 = (uint64_t *)translations->s1_page_tables[2].hva;

        for (uint64_t curr_l1_id = 0; curr_l1_id < ENTRIES_PER_PAGE; curr_l1_id += 1) {
            uint64_t l1e = l1[curr_l1_id];
            if (!(l1e & S1_TABLE_VALID))
                continue;
            ASSERT(curr_l1_id == 0, "dbg_dump_guest_page_tables");

            uint64_t l2_ipa = l1e & 0x0000FFFFFFFFF000ULL;
            ASSERT(l2_ipa == translations->s1_page_tables[1].gpa, "dbg_dump_guest_page_tables");
            uint64_t *l2 = (uint64_t *)translations->s1_page_tables[1].hva;

            for (uint64_t curr_l2_id = 0; curr_l2_id < ENTRIES_PER_PAGE; curr_l2_id += 1) {
                uint64_t l2e = l2[curr_l2_id];
                if (!(l2e & S1_TABLE_VALID))
                    continue;
                ASSERT(curr_l2_id == 0, "dbg_dump_guest_page_tables");

                uint64_t l3_ipa = l2e & 0x0000FFFFFFFFF000ULL;
                ASSERT(l3_ipa == translations->s1_page_tables[0].gpa, "dbg_dump_guest_page_tables");
                uint64_t *l3 = (uint64_t *)translations->s1_page_tables[0].hva;

                for (uint64_t curr_l3_id = 0; curr_l3_id < ENTRIES_PER_PAGE; curr_l3_id += 1) {
                    uint64_t l3e = l3[curr_l3_id];
                    if (!(l3e & S1_PTE_VALID))
                        continue;

                    uint64_t ipa = l3e & 0x0000FFFFFFFFF000ULL;
                    uint64_t gva = (curr_l0_id << S2_L0_SHIFT) | (curr_l1_id << S2_L1_SHIFT) |
                                   (curr_l2_id << S2_L2_SHIFT) | (curr_l3_id << S2_L3_SHIFT);

                    // 解析S1PT权限位：AP[7:6], PXN[53], XN[54]
                    uint64_t ap = (l3e >> S1_PTE_AP_SHIFT) & 3;
                    char v = (l3e & S1_PTE_VALID) ? 'V' : '-';
                    char r = (ap == 1 || ap == 3) ? 'R' : '-';
                    char w = (ap == 0 || ap == 1) ? 'W' : '-';
                    char u = (ap == 1 || ap == 3) ? 'U' : '-';
                    char x = (l3e & S1_PTE_XN) ? '-' : 'X';
                    char px = (l3e & S1_PTE_PXN) ? '-' : 'P';
                    char af = (l3e & S1_PTE_AF) ? 'A' : '-';

                    printk(KERN_INFO "GVA: 0x%-16llx -> IPA: 0x%-16llx; %c%c%c%c%c%c%c\n", gva,
                           ipa, v, r, w, u, x, px, af);
                }
            }
        }
    }
    return 0;
}

// dbg_dump_ept - 遍历并打印S2PT(Stage-2页表)
// 打印每个有效L3条目的IPA→HPA映射和S2PT权限(V/R/W/X/A)
int dbg_dump_ept(int actor_id)
{
    printk(KERN_INFO "------- S2PT(Stage-2页表/EPT等价) dump for actor %d ---------------\n", actor_id);
    actor_s2_page_table_t *s2_pt = &allocated_s2_page_tables[actor_id];

    uint64_t *l0 = s2_pt->l0;
    for (uint64_t curr_l0_id = 0; curr_l0_id < ENTRIES_PER_PAGE; curr_l0_id += 1) {
        uint64_t l0e = l0[curr_l0_id];
        if (!(l0e & S2_TABLE_VALID))
            continue;
        uint64_t l1_hpa = l0e & 0x0000FFFFFFFFF000ULL;
        ASSERT((l1_hpa & ~0xFFF) == vmalloc_to_phys(s2_pt->l1), "dbg_dump_ept");
        uint64_t *l1 = s2_pt->l1;

        for (uint64_t curr_l1_id = 0; curr_l1_id < ENTRIES_PER_PAGE; curr_l1_id += 1) {
            uint64_t l1e = l1[curr_l1_id];
            if (!(l1e & S2_TABLE_VALID))
                continue;
            uint64_t l2_hpa = l1e & 0x0000FFFFFFFFF000ULL;
            ASSERT((l2_hpa & ~0xFFF) == vmalloc_to_phys(s2_pt->l2), "dbg_dump_ept");
            uint64_t *l2 = s2_pt->l2;

            for (uint64_t curr_l2_id = 0; curr_l2_id < ENTRIES_PER_PAGE; curr_l2_id += 1) {
                uint64_t l2e = l2[curr_l2_id];
                if (!(l2e & S2_TABLE_VALID))
                    continue;
                uint64_t l3_hpa = l2e & 0x0000FFFFFFFFF000ULL;
                ASSERT((l3_hpa & ~0xFFF) == vmalloc_to_phys(s2_pt->l3), "dbg_dump_ept");
                uint64_t *l3 = s2_pt->l3;

                for (uint64_t curr_l3_id = 0; curr_l3_id < ENTRIES_PER_PAGE; curr_l3_id += 1) {
                    uint64_t l3e = l3[curr_l3_id];
                    if (!S2_PTE_IS_PRESENT(l3e))
                        continue;

                    uint64_t ipa = (curr_l0_id << S2_L0_SHIFT) | (curr_l1_id << S2_L1_SHIFT) |
                                   (curr_l2_id << S2_L2_SHIFT) | (curr_l3_id << S2_L3_SHIFT);

                    // HPA-IPA碰撞过滤：同一HPA可能映射到多个IPA
                    if (enable_hpa_gpa_collisions &&
                        !gpa_is_valid((hgpa_t *)&guest_memory_translations[actor_id], ipa)) {
                        continue;
                    }

                    uint64_t hpa = l3e & 0x0000FFFFFFFFF000ULL;
                    void *hva = phys_to_vmalloc(hpa, actor_id);
                    char v = S2_PTE_IS_PRESENT(l3e) ? 'V' : '-';
                    char r = S2_PTE_IS_READABLE(l3e) ? 'R' : '-';
                    char w = S2_PTE_IS_WRITABLE(l3e) ? 'W' : '-';
                    char x = S2_PTE_IS_EXECUTABLE(l3e) ? 'X' : '-';
                    char af = (l3e & S2_PTE_AF) ? 'A' : '-';

                    printk(KERN_INFO
                           "IPA: 0x%-16llx -> HPA: 0x%-16llx (HVA: 0x%-16llx); %c%c%c%c%c\n",
                           ipa, hpa, (uint64_t)hva, v, r, w, x, af);
                }
            }
        }
    }
    return 0;
}

// =================================================================================================

// free_guest_page_tables - 释放所有页表相关内存
// 安全释放S1PT/S2PT每级页面、异常向量表、翻译表、VTTBR_EL2指针等
void free_guest_page_tables(void)
{
    if (allocated_s1_page_tables) {
        for (int i = 0; i < n_actors; i++) {
            SAFE_VFREE(allocated_s1_page_tables[i].l0);
            SAFE_VFREE(allocated_s1_page_tables[i].l1);
            SAFE_VFREE(allocated_s1_page_tables[i].l2);
            SAFE_VFREE(allocated_s1_page_tables[i].l3);
        }
    }
    if (allocated_s2_page_tables) {
        for (int i = 0; i < n_actors; i++) {
            SAFE_VFREE(allocated_s2_page_tables[i].l0);
            SAFE_VFREE(allocated_s2_page_tables[i].l1);
            SAFE_VFREE(allocated_s2_page_tables[i].l2);
            SAFE_VFREE(allocated_s2_page_tables[i].l3);
        }
    }
    SAFE_VFREE(allocated_s1_page_tables);
    SAFE_VFREE(allocated_s2_page_tables);
    SAFE_VFREE(allocated_exception_vectors);
    SAFE_FREE(guest_memory_translations);
    SAFE_FREE(s2pt_ptr);
    SAFE_FREE(hvc_page);
    SAFE_FREE(faulty_s1_ptes);
    SAFE_FREE(faulty_s2_ptes);
}
