/// File: Sandbox memory management
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "hardware_desc.h"

#include "actor.h"
#include "code_loader.h" // loaded_test_case_entry
#include "main.h"        // set_memory_x, set_memory_nx
#include "sandbox_manager.h"
#include "shortcuts.h"
#include "test_case_parser.h"

#include "page_tables_guest.h"
#include "page_tables_host.h"

// 全局沙箱指针，存储沙箱的代码区、数据区和util区的地址
sandbox_t *sandbox = NULL; // global

// Util+Data分配状态（使用alloc_pages+vmap策略）
// 为什么用alloc_pages+vmap而不是kmalloc或vmalloc：
//   kmalloc: 物理连续但内核直接映射可能使用大页(huge pages)，无法操作4KB PTE
//   vmalloc: 使用4KB页表但物理不连续，Prime+Probe需要物理连续
//   alloc_pages+vmap: 物理连续且创建新的4KB页表，满足两个约束
static struct {
    void *vaddr_unaligned;    // vmap映射的虚拟地址（未对齐）
    void *vaddr_aligned;      // 对齐到2页(8KB)边界的虚拟地址
    struct page **page_array; // 页指针数组，用于vmap映射
    int num_pages;            // 分配的页数
} util_data = {NULL, NULL, NULL, 0};

// 代码区的虚拟地址（使用vmalloc分配，不需要物理连续）
static void *code = NULL;
// 代码区之前设置为可执行(X)的页数，用于恢复时设回不可执行(NX)
static size_t old_x_size = 0;

/// @brief 释放util_data的分配（vmap虚拟映射 + alloc_pages物理页）
static void safe_free_util_data(void)
{
    // 先解除vmap的虚拟映射
    if (util_data.vaddr_unaligned) {
        vunmap(util_data.vaddr_unaligned);
        util_data.vaddr_unaligned = NULL;
        util_data.vaddr_aligned = NULL;
    }
    // 再释放alloc_pages分配的物理页和页指针数组
    if (util_data.page_array) {
        int order = get_order(util_data.num_pages * PAGE_SIZE);
        __free_pages(util_data.page_array[0], order);
        kfree(util_data.page_array);
        util_data.page_array = NULL;
    }
}

/// @brief 释放代码区的vmalloc分配，先将内存设为不可执行(NX)再释放
static void safe_free_code(void)
{
    if (code) {
        // 将代码区从可执行(X)恢复为不可执行(NX)，防止安全风险
        set_memory_nx((unsigned long)code, old_x_size);
        SAFE_VFREE(code);
        loaded_test_case_entry = NULL;
    }
}

/// @brief 在内存分配完成后初始化沙箱指针，将代码区、数据区、util区地址绑定到sandbox结构
/// @return 0表示成功，-ENOMEM表示内存分配失败
static int init_sandbox_pointers(void)
{
    if (!sandbox) {
        sandbox = CHECKED_MALLOC(sizeof(sandbox_t));
    }
    // 数据区紧跟在util区之后，布局为: [util区 | actor_data[0] | actor_data[1] | ...]
    sandbox->data = (actor_data_t *)((unsigned long)util_data.vaddr_aligned + sizeof(util_t));
    // 代码区独立分配（vmalloc），每个actor有自己的代码段
    sandbox->code = (actor_code_t *)code;
    // util区从8KB对齐地址开始
    sandbox->util = (util_t *)util_data.vaddr_aligned;
    loaded_test_case_entry = code;
    return 0;
}

/// @brief Allocate memory for the Util and Data areas of the sandbox
/// @details
/// Constraints:
/// 1. Physical Continuity - Prime+Probe attacks require contiguous physical pages for PIPT caches
/// 2. 4KB Page Tables - Executor must manipulate individual PTEs (impossible with huge pages)
/// 3. 8KB Alignment - Memory must be aligned to 2-page boundary
///
/// Solution: alloc_pages() + vmap()
/// - cannot use kmalloc: physically contiguous BUT uses huge pages in direct mapping
/// - cannot use vmalloc: uses 4KB PTEs BUT not physically contiguous
/// - solution -> alloc_pages + vmap: physically contiguous AND creates new 4KB page tables
///
/// @param n_actors Number of actors
/// @return 0 on success, -ENOMEM on failure
static int allocate_util_and_data(size_t n_actors)
{
    // 先释放之前的分配（如果存在）
    safe_free_util_data();

    // 计算所需的内存大小
    // util区存储共享变量（测量值、保存的寄存器等），data区存储每个actor的数据
    const size_t util_mem_size = sizeof(util_t);
    const size_t data_mem_size = n_actors * sizeof(actor_data_t);
    const size_t mem_size = util_mem_size + data_mem_size;
    // 多分配4KB以确保可以将地址对齐到8KB(2页)边界
    // 因为vmap返回的地址可能只对齐到4KB，需要额外空间做8KB对齐调整
    size_t alloc_size = mem_size + 0x1000;
    util_data.num_pages = (alloc_size + PAGE_SIZE - 1) / PAGE_SIZE;
    int order = get_order(alloc_size);

    // 使用alloc_pages分配物理连续的页面
    // __GFP_ZERO确保页面内容为零，GFP_KERNEL为内核级分配
    // 物理连续性是Prime+Probe攻击的前提：PIPT缓存需要连续物理页
    struct page *page = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
    if (!page) {
        PRINT_ERR("Error allocating util_and_data pages\n");
        return -ENOMEM;
    }

    // 构建页指针数组，用于vmap映射
    util_data.page_array = kmalloc(util_data.num_pages * sizeof(struct page *), GFP_KERNEL);
    if (!util_data.page_array) {
        __free_pages(page, order);
        PRINT_ERR("Error allocating page array\n");
        return -ENOMEM;
    }

    // 将alloc_pages返回的连续物理页拆分为单独的页指针
    // alloc_pages返回第一页的指针，page+i指向第i页
    for (int i = 0; i < util_data.num_pages; i++) {
        util_data.page_array[i] = page + i;
    }

    // 使用vmap将物理页映射到内核虚拟地址空间
    // vmap会创建新的4KB页表（不是大页），这对于PTE操作至关重要
    // PAGE_KERNEL权限：内核可读写，不可执行
    util_data.vaddr_unaligned =
        vmap(util_data.page_array, util_data.num_pages, VM_MAP, PAGE_KERNEL);
    if (!util_data.vaddr_unaligned) {
        kfree(util_data.page_array);
        __free_pages(page, order);
        util_data.page_array = NULL;
        PRINT_ERR("Error mapping util_and_data pages\n");
        return -ENOMEM;
    }

    // 将虚拟地址对齐到2页(8KB=0x2000)边界
    // 8KB对齐确保actor_data的main_area从8KB边界开始，
    // 这对于基于偏移量的汇编代码访问至关重要
    unsigned long addr = (unsigned long)util_data.vaddr_unaligned;
    util_data.vaddr_aligned = (void *)ALIGN(addr, 0x2000);

    return 0;
}

/// @brief Allocate memory for the Code area of the sandbox
/// @details
/// Uses vmalloc (physical continuity not required). Provides 4KB page tables for PTE
/// manipulation and executable memory support via set_memory_x().
/// @param n_actors Number of actors (each gets its own code area)
/// @return 0 on success, error code on failure
static int allocate_code(size_t n_actors)
{
    // 先释放之前的代码区分配
    safe_free_code();

    // 使用vmalloc为代码区分配内存
    // 代码区不需要物理连续（Prime+Probe只在数据区进行）
    // vmalloc自动创建4KB页表，支持后续的PTE权限操作
    code = CHECKED_VMALLOC(n_actors * sizeof(actor_code_t));
    // 重置代码区，填充NOP指令并在起始处放置ret指令
    reset_code_area();

    // 将代码区设置为可执行(X)
    // vmalloc默认分配不可执行内存，需要通过set_memory_x改为可执行
    size_t code_size = n_actors * sizeof(actor_code_t);
    old_x_size = DIV_ROUND_UP(code_size, PAGE_SIZE);
    set_memory_x((unsigned long)code, old_x_size);

    return 0;
}

/// @brief Clears out the code area from previous executions and fills the area with NOPs
/// @param void
/// @return void
void reset_code_area(void)
{
    // 将代码区填充为NOP指令（0x90是x86 NOP，0xd503201f是ARM64 NOP）
    // NOP填充确保未使用的代码区不会引发意外行为
#if defined(ARCH_X86_64)
    memset(code, 0x90, sizeof(actor_code_t) * n_actors);
#elif defined(ARCH_ARM)
    for (int i = 0; i < n_actors * sizeof(actor_code_t) / 4; i += 1)
        ((uint32_t *)code)[i] = 0xd503201f;
#endif

    // 在代码区起始处放置一条ret/return指令
    // 作为默认的"空"测试用例入口，直接返回不做任何操作
#if defined(ARCH_X86_64)
    ((uint8_t *)code)[0] = '\xC3';
#elif defined(ARCH_ARM)
    ((uint32_t *)code)[0] = 0xd65f03c0;
#endif
}

int allocate_sandbox(void)
{
    int err = 0;
    static int old_n_actors = 1;

    // 当actor数量增加时，重新分配沙箱内存
    // 如果数量不变则复用之前的分配，避免频繁分配释放
    if (old_n_actors < n_actors) {
        err = allocate_util_and_data(n_actors);
        CHECK_ERR("allocate_util_and_data");

        err = allocate_code(n_actors);
        CHECK_ERR("allocate_code");

        err = init_sandbox_pointers();
        CHECK_ERR("init_sandbox_pointers");
    }

    // 清零整个util+data区，确保每次测量前状态干净
    memset(util_data.vaddr_aligned, 0, sizeof(util_t) + n_actors * sizeof(actor_data_t));

    // 缓存宿主机页表项(PTPs)指针，用于后续快速修改PTE权限
    err = cache_host_pteps();
    CHECK_ERR("cache_host_pteps");

    // 如果测试用例包含虚拟机(VM) actor，需要额外的页表管理
    // VM actor运行在客户机(Guest)模式下，需要EPT(扩展页表)支持
    if (test_case->features.includes_vm_actors) {
        err = allocate_guest_page_tables();
        CHECK_ERR("allocate_guest_page_tables");

        err = map_sandbox_to_guest_memory();
        CHECK_ERR("map_sandbox_to_guest_memory");
    }
    old_n_actors = n_actors;

    return err;
}

/// @brief Returns the number of pages allocated for the sandbox, including util area, code and data
/// @param void
/// @return number of pages; -1 on error
int get_sandbox_size_pages(void)
{
    if (!sandbox)
        return -1;

    return DIV_ROUND_UP(sizeof(util_t), PAGE_SIZE) +
           DIV_ROUND_UP(sizeof(actor_data_t) * n_actors, PAGE_SIZE) +
           DIV_ROUND_UP(sizeof(actor_code_t) * n_actors, PAGE_SIZE);
}

/// @brief Sets PTE values for the sandbox based on the current test case configuration
/// @param void
/// @return 0 on success; -1 on error
int set_sandbox_page_tables(void)
{
    // 保存原始的宿主机页表权限，以便执行完毕后恢复
    int err = store_orig_host_permissions();
    CHECK_ERR("store_orig_host_permissions");

    // 如果测试用例包含用户态(user) actor，修改相关页面的PTE权限
    // 用户态actor需要特殊的页表权限设置（如用户可访问位）
    if (test_case->features.includes_user_actors) {
        err = set_user_pages();
        CHECK_ERR("set_user_pages");
    }
    return 0;
}

void restore_orig_sandbox_page_tables(void) { restore_orig_host_permissions(); }

/// @brief 快速修改faulty页面的PTE权限，根据actor_t->data_permissions设置
/// 同时修改三级页表权限：宿主机页表、客户机页表、EPT(扩展页表)
void set_faulty_page_permissions(void)
{
    set_faulty_page_host_permissions();
    set_faulty_page_guest_permissions();
    set_faulty_page_ept_permissions();
}

/// @brief 快速恢复faulty页面的原始PTE权限
void restore_faulty_page_permissions(void)
{
    restore_faulty_page_host_permissions();
    restore_faulty_page_guest_permissions();
    restore_faulty_page_ept_permissions();
}

// =================================================================================================
int init_sandbox_manager(void)
{
    // 初始化时分配1个actor的沙箱（最小配置）
    int err = allocate_util_and_data(1);
    CHECK_ERR("allocate_util_and_data");

    err = allocate_code(1);
    CHECK_ERR("allocate_code");

    err = init_sandbox_pointers();
    CHECK_ERR("init_sandbox_pointers");

    // 验证第一个actor的main_area是否8KB对齐
    // main_area的对齐对于汇编代码中基于偏移量的访问至关重要
    int offset = (unsigned long)sandbox->data[0].main_area % 0x2000;
    ASSERT(offset == 0, "init_sandbox_manager");

    // 自检：由于汇编代码使用硬编码偏移量访问沙箱数据结构(sandbox_constants.h)，
    // 必须验证C结构体的实际布局与硬编码偏移量是否一致
    // 如果结构体定义改变而偏移量未更新，会导致访问错误的数据区域
    util_t *util = sandbox->util;
    // 验证L1D预取(priming)区域的偏移量
    ASSERT(&util->l1d_priming_area[0] - (uint8_t *)util == L1D_PRIMING_OFFSET, "init_sandbox");
    // 验证保存的RSP寄存器偏移量
    ASSERT((uint8_t *)&util->vars.stored_rsp - (uint8_t *)util == STORED_RSP_OFFSET,
           "init_sandbox");
    // 验证测量值(measurement)偏移量
    ASSERT((uint8_t *)&util->vars.latest_measurement - (uint8_t *)util == MEASUREMENT_OFFSET,
           "init_sandbox");
    actor_data_t *data = &sandbox->data[0];
    // 验证main_area相对于util起始的偏移量
    ASSERT(&data->main_area[0] - (uint8_t *)util == UTIL_REL_TO_MAIN, "init_sandbox");
    // 验证宏栈(macro_stack)顶部偏移量
    ASSERT(&data->main_area[0] - &data->macro_stack[64] == MACRO_STACK_TOP_OFFSET, "init_sandbox");
    // 验证faulty_area相对于main_area的偏移量
    // faulty_area用于测试页错误(page fault)相关的侧信道漏洞
    ASSERT(&data->faulty_area[0] - &data->main_area[0] == FAULTY_AREA_OFFSET, "init_sandbox");
    // 验证寄存器初始化区域偏移量
    ASSERT(&data->reg_init_area[0] - &data->main_area[0] == REG_INIT_OFFSET, "init_sandbox");
    // 验证溢出保护(overflow_pad)偏移量
    ASSERT(&data->overflow_pad[0] - &data->main_area[0] == OVERFLOW_PAD_OFFSET, "init_sandbox");
    // 验证测量值(measurement_t)结构体大小
    ASSERT(sizeof(measurement_t) == MEASUREMENT_SIZE, "init_sandbox");

    return 0;
}

void free_sandbox_manager(void)
{
    safe_free_util_data();
    safe_free_code();
    free_guest_page_tables();
}
