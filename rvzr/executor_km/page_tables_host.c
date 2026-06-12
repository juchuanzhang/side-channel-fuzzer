/// File:
///  - Page Table management
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

// 【页表管理总体架构】
// 本文件实现了"Enter, Exit, Page Fault, Leak"论文Section 5.2中描述的宿主机(Host)页表管理功能。
// 
// 核心思路：fuzzer通过直接修改内核页表项(PTE)来控制沙箱页面的访问权限，从而构造
// 微架构侧信道攻击条件。整个流程如下：
//   1. get_pte(): 手动遍历内核页表，获取任意内核虚拟地址对应的PTE指针
//   2. cache_host_pteps(): 在初始化时缓存所有沙箱页面的PTE指针，避免每次都重新遍历页表
//   3. store_orig_host_permissions(): 保存沙箱页面的原始PTE值，用于后续恢复
//   4. set_user_pages(): 为用户态(user)actor设置页面权限（添加U/S位），使其可在Ring 3访问
//   5. set_faulty_page_host_permissions(): 修改faulty页面的PTE权限位，构造侧信道条件
//   6. restore_faulty_page_host_permissions(): 快速恢复faulty页面的原始权限
//   7. restore_orig_host_permissions(): 恢复所有沙箱页面的原始权限（模块卸载时使用）
//
// 页表遍历的关键挑战：
//   - x86_64使用单一CR3寄存器，每次上下文切换都会改变pgd基址，因此每次调用get_pte()
//     都需要从CR3重新读取pgd基址
//   - ARM64使用TTBR0/TTBR1双寄存器，内核页表基址(TTBR1_EL1)在启动后不变，可安全缓存

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>

#include "actor.h"
#include "hardware_desc.h"
#include "sandbox_manager.h"
#include "shortcuts.h"

#include "page_tables_common.h"
#include "page_tables_host.h"

#if defined(ARCH_X86_64)
#include <asm/pgtable_types.h> // _PAGE_PSE
#include <asm/special_insns.h> // read_cr3_pa()
#elif defined(ARCH_ARM)
#include <asm/pgtable-hwdef.h> // PUD_TYPE_TABLE, PMD_TYPE_TABLE
#endif

#if defined(ARCH_X86_64)
#define IS_PUD_LEAF(pud) ((pud_val(pud) & _PAGE_PSE) != 0)
#define IS_PMD_LEAF(pmd) ((pmd_val(pmd) & _PAGE_PSE) != 0)
#elif defined(ARCH_ARM)
#define IS_PUD_LEAF(pud) ((pud_val(pud) & PUD_TYPE_MASK) != PUD_TYPE_TABLE)
#define IS_PMD_LEAF(pmd) ((pmd_val(pmd) & PMD_TYPE_MASK) != PMD_TYPE_TABLE)
#endif

sandbox_pteps_t *sandbox_pteps;

static sandbox_ptes_t *orig_ptes;
static pte_t_ *faulty_ptes = NULL;

// =================================================================================================
// Kernel top-level page-table base resolution
//
// `get_pte()` walks the kernel/vmalloc half of the address space and therefore
// needs the kernel's top-level page-table (pgd) base. How that base is obtained
// — and whether it can be cached — differs fundamentally between the two
// supported architectures.
//
// We intentionally avoid reading symbols like `swapper_pg_dir` / `init_mm` via
// kallsyms: kernels built with CONFIG_KALLSYMS_ALL=n do not expose data
// symbols to modules, and the layout of `struct mm_struct` is not part of any
// stable ABI either.
// =================================================================================================
// 【内核页表基址获取】
// get_pte()需要知道内核顶层页表(pgd)的基址才能开始遍历。
// 两种架构的处理方式不同：
//   - ARM64: 内核页表基址(TTBR1_EL1)在系统启动后固定不变，可安全缓存
//   - x86_64: 单一CR3寄存器在每次上下文切换时更新，不能缓存，必须每次从CR3读取
// 注意：我们不使用kallsyms读取swapper_pg_dir等符号，因为CONFIG_KALLSYMS_ALL=n的内核
// 不向模块暴露数据符号，且mm_struct布局不属于稳定ABI

#if defined(ARCH_ARM)
// On arm64 the CPU consults two separate registers for translation: TTBR0_EL1
// for user VAs and TTBR1_EL1 for kernel/vmalloc VAs. TTBR1_EL1 is installed
// once at boot to point at `swapper_pg_dir`, a statically allocated page that
// lives for the lifetime of the system and is never replaced on context switch
// (only TTBR0_EL1 changes). So the value is stable and safe to cache.
// 【ARM64页表基址】ARM64使用两个独立寄存器：TTBR0_EL1(用户空间)和TTBR1_EL1(内核空间)。
// TTBR1_EL1在启动时设置为swapper_pg_dir，且上下文切换时不会改变（仅TTBR0改变），
// 因此其值稳定可缓存。
static pgd_t *arm64_kernel_pgd = NULL;

static int init_kernel_pgd_base(void)
{
    unsigned long ttbr1;
    phys_addr_t pa;

    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));

    // Reverse the kernel's `phys_to_ttbr` encoding. With FEAT_LPA active
    // (CONFIG_ARM64_PA_BITS_52), PA[51:48] is packed into TTBR[5:2] while
    // PA[47:12] remains in TTBR[47:12]. Otherwise the PA sits in [47:12]
    // directly.
#ifdef CONFIG_ARM64_PA_BITS_52
    pa = (ttbr1 & GENMASK_ULL(47, PAGE_SHIFT)) | ((ttbr1 & GENMASK_ULL(5, 2)) << 46);
#else
    pa = ttbr1 & GENMASK_ULL(47, PAGE_SHIFT);
#endif

    arm64_kernel_pgd = (pgd_t *)phys_to_virt(pa);
    if (!arm64_kernel_pgd) {
        PRINT_ERR("init_kernel_pgd_base: failed to decode TTBR1_EL1=0x%lx\n", ttbr1);
        return -ENODEV;
    }
    return 0;
}

static inline pgd_t *get_kernel_pgd_base(void) { return arm64_kernel_pgd; }

#elif defined(ARCH_X86_64)
// On x86_64 there is no dedicated kernel page-table register: a single CR3
// holds the pgd for *both* halves of the address space, and it is reloaded on
// every context switch to point at the currently scheduled task's `mm->pgd`.
// Two consequences:
//
//   1. Lifetime: the pgd page is owned by some task's mm_struct. When that
//      task exits and its last mm reference drops, `pgd_free()` returns the
//      page to the allocator. A pointer captured at `init_module()` time
//      would dangle — typically the insmod task itself exits shortly after
//      loading the module.
//   2. Identity: which pgd is active depends on the task scheduled on the
//      CPU at call time, so a single cached pointer cannot represent "the"
//      kernel pgd.
//
// Reading CR3 on every call sidesteps both: the kernel keeps the upper-half
// (kernel/vmalloc) entries of every pgd synchronized, so walking whichever
// pgd is live yields the correct PTE for a kernel VA regardless of context.
// 【x86_64页表基址】x86_64只有CR3寄存器管理整个地址空间，每次上下文切换都会更新CR3。
// 因此：1) 不能缓存pgd指针（insmod进程退出后指针悬空）；2) 不同进程有不同的pgd。
// 解决方案：每次调用时从CR3读取当前pgd基址。内核保证所有进程的pgd中
// 内核/vmalloc部分(上半部分)的条目是同步的，所以无论哪个进程的pgd，
// 遍历结果都相同。
static inline int init_kernel_pgd_base(void) { return 0; }

static inline pgd_t *get_kernel_pgd_base(void) { return (pgd_t *)__va(read_cr3_pa()); }

#else
#error "Unsupported architecture: cannot determine kernel pgd base"
#endif


/// @brief Walk the kernel page tables for a kernel/vmalloc VA and return a
///        pointer to its leaf PTE.
///
/// The returned pointer aliases the live page-table entry; writes through
/// it modify the mapping directly and the caller is responsible for any
/// required TLB invalidation.
///
/// @param hva  Kernel VA to translate. Must lie in the vmalloc or direct-map
///             (kmalloc) range; other addresses are rejected.
/// @return Pointer to the leaf PTE, or NULL if the address is out of range,
///         the pgd base is uninitialized, or the walk hits an unmapped or
///         malformed entry.
// 【get_pte() - 内核页表遍历】这是整个页表管理系统的核心函数。
// 功能：给定一个内核虚拟地址(HVA)，手动遍历4级(或5级)内核页表，返回其叶级PTE的指针。
// 原理：x86_64页表结构为 PGD(PML4) -> P4D -> PUD(PDPT) -> PMD(PD) -> PTE(PT)，
//       每级使用虚拟地址的不同位段作为索引查找下一级页表。
// 关键特性：返回的指针直接指向活跃的页表项，写入该指针可直接修改映射，
//           调用者需要负责TLB失效(native_page_invalidate)。
// 限制：仅接受vmalloc或kmalloc(直接映射)范围内的地址；拒绝大页映射(1GiB/2MiB)。
pte_t *get_pte(uint64_t hva)
{
    pgd_t *pgd_base;

    // Make sure we are in vmalloc area
    // 【地址合法性检查】确保目标地址在vmalloc或kmalloc(直接映射)范围内，
    // 否则页表遍历可能产生错误结果或访问非法内存
    if (!is_vmalloc_addr((void *)hva) && !virt_addr_valid((void *)hva)) {
        PRINT_ERR("get_pte: address not in vmalloc or kmalloc area");
        return NULL;
    }

    pgd_base = get_kernel_pgd_base();
    // 【获取页表基址】从CR3(x86_64)或TTBR1_EL1(ARM64)获取当前内核页表的顶层基址
    if (!pgd_base) {
        PRINT_ERR("get_pte: kernel pgd base not initialized");
        return NULL;
    }

    // Do a page walk
    // 【页表遍历过程】以下逐级遍历5级页表结构，每一级使用虚拟地址的对应位段作为索引
    // x86_64 5级页表: PGD(L0) -> P4D(L1) -> PUD(L2) -> PMD(L3) -> PTE(L4)
    // 每级页表包含512个条目(9位索引)，使用READ_ONCE确保原子读取
    
    // - Level 0: 页全局目录(PGD/PML4)，使用虚拟地址的[47:39]位作为索引
    pgd_t *pgdp = pgd_offset_pgd(pgd_base, hva);
    pgd_t pgd = READ_ONCE(*pgdp);
    if (pgd_none(pgd)) {
        PRINT_ERR("get_pte: pgd_none");
        return NULL;
    }

    // - Level 1: P4D层（在5级页表中使用，4级页表中此层被跳过但内核API仍提供统一接口）
    p4d_t *p4dp = p4d_offset(pgdp, hva);
    p4d_t p4d = READ_ONCE(*p4dp);
    if (p4d_none(p4d)) {
        PRINT_ERR("get_pte: p4d_none");
        return NULL;
    }

    // - Level 2: 页上层目录(PUD/PDPT)，使用虚拟地址的[38:30]位作为索引
    pud_t *pudp = pud_offset(p4dp, hva);
    pud_t pud = READ_ONCE(*pudp);
    if (pud_none(pud)) {
        PRINT_ERR("get_pte: pud_none");
        return NULL;
    }
    // Reject huge (1 GiB) leaf mappings: descending past a block entry would
    // synthesize a bogus PMD pointer.
    // 【拒绝1GiB大页映射】如果PUD是叶节点(1GiB大页)，则不能继续向下遍历，
    // 因为大页条目中编码的是物理页帧地址而非下一级页表地址，继续遍历会产生虚假指针
    if (IS_PUD_LEAF(pud)) {
        PRINT_ERR("get_pte: pud is a huge (1 GiB) leaf mapping\n");
        return NULL;
    }
    if (pud_bad(pud)) {
        PRINT_ERR("get_pte: pud_bad");
        return NULL;
    }

    // - Level 3: 页中间目录(PMD/PD)，使用虚拟地址的[29:21]位作为索引
    pmd_t *pmdp = pmd_offset(pudp, hva);
    pmd_t pmd = READ_ONCE(*pmdp);
    if (pmd_none(pmd)) {
        PRINT_ERR("get_pte: pmd_none");
        return NULL;
    }
    // Reject large (2 MiB) leaf mappings.
    // 【拒绝2MiB大页映射】与1GiB大页同理，2MiB大页(PMD叶节点)也不能继续向下遍历
    if (IS_PMD_LEAF(pmd)) {
        PRINT_ERR("get_pte: pmd is a large (2 MiB) leaf mapping\n");
        return NULL;
    }
    if (pmd_bad(pmd)) {
        PRINT_ERR("get_pte: pmd_bad");
        return NULL;
    }

    // - Level 4 (leaf): 页表条目(PTE)，使用虚拟地址的[20:12]位作为索引
    // 【叶级PTE】这是最终目标，PTE中编码了物理页帧地址和权限位(Present/Writable/User/等)
    // 返回的指针直接指向活跃的页表条目，后续可直接修改权限位
    pte_t *pte = pte_offset_kernel(pmdp, hva);
    ASSERT_ENULL(pte_present(*pte), "get_pte");

    return pte;
}

// =================================================================================================
// Manipulation of Host Page Tables
// =================================================================================================
// 【宿主机页表操作】以下函数用于管理沙箱页面的宿主机PTE权限，是fuzzer构造侧信道条件的核心
// 操作流程：缓存PTE指针 -> 保存原始权限 -> 修改权限 -> 恢复权限

/// @brief Cache the PTE pointers for all sandbox pages.
/// @param void
/// @return 0 on success, -1 on failure
// 【cache_host_pteps - 缓存PTE指针】
// 作用：遍历所有沙箱页面的虚拟地址，调用get_pte()获取每个页面的PTE指针并缓存。
// 为什么需要缓存？
//   1. get_pte()需要5级页表遍历，开销较大，频繁调用会严重影响fuzzer性能
//   2. 在fuzzer执行过程中需要快速修改PTE权限，缓存后可直接写入而不需要重新遍历
//   3. 沙箱页面的虚拟地址在分配后固定不变，对应的PTE指针也不会改变
// 缓存三类页面的PTE指针：
//   - util_pteps: 工具页面（用于存储测量结果），所有actor共享
//   - data_pteps: 数据页面，每个actor有独立的N_DATA_PAGES_PER_ACTOR个页面
//   - code_pteps: 代码页面，每个actor有独立的N_CODE_PAGES_PER_ACTOR个页面
int cache_host_pteps(void)
{
    ASSERT(sandbox_pteps != NULL, "cache_host_pteps");
    ASSERT(sandbox != NULL, "cache_host_pteps");

    static int old_n_actors = 1;
    if (n_actors > old_n_actors) {
        SAFE_FREE(sandbox_pteps->data_pteps);
        SAFE_FREE(sandbox_pteps->code_pteps);
        sandbox_pteps->data_pteps =
            CHECKED_ZALLOC(N_DATA_PAGES_PER_ACTOR * n_actors * sizeof(pte_t_ *));
        sandbox_pteps->code_pteps =
            CHECKED_ZALLOC(N_CODE_PAGES_PER_ACTOR * n_actors * sizeof(pte_t_ *));
    }
    old_n_actors = n_actors;

    // cache the PTE pointers for the util pages
    for (int i = 0; i < N_UTIL_PAGES; i++) {
        uint64_t va = (uint64_t)sandbox->util + i * PAGE_SIZE;
        pte_t *ptep = get_pte(va);
        ASSERT(ptep != NULL, "cache_host_pteps");
        sandbox_pteps->util_pteps[i] = (pte_t_ *)&ptep->pte;
    }

    // cache the PTE pointers for the code and data pages of the sandbox
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // cache the PTE pointers for the data pages of the actor
        for (int i = 0; i < N_DATA_PAGES_PER_ACTOR; i++) {
            uint64_t va = ((uint64_t)&sandbox->data[actor_id]) + i * PAGE_SIZE;
            pte_t *ptep = get_pte(va);
            ASSERT(ptep != NULL, "cache_host_pteps");
            sandbox_pteps->data_pteps[actor_id * N_DATA_PAGES_PER_ACTOR + i] = (pte_t_ *)&ptep->pte;
        }
        // cache the PTE pointers for the code pages of the actor
        for (int i = 0; i < N_CODE_PAGES_PER_ACTOR; i++) {
            uint64_t va = ((uint64_t)&sandbox->code[actor_id]) + i * PAGE_SIZE;
            pte_t *ptep = get_pte(va);
            ASSERT(ptep != NULL, "cache_host_pteps");
            sandbox_pteps->code_pteps[actor_id * N_CODE_PAGES_PER_ACTOR + i] = (pte_t_ *)&ptep->pte;
        }
    }
    return 0;
}

/// @brief Preserve the original PTEs for all sandbox pages.
/// @param void
/// @return 0 on success, -1 on failure
// 【store_orig_host_permissions - 保存原始权限】
// 作用：在修改沙箱页面权限之前，保存每个页面的原始PTE值。
// 原因：fuzzer运行过程中会反复修改PTE权限位（如清除Present位、设置U/S位等），
//       在fuzzer迭代结束或模块卸载时，必须恢复原始权限以避免破坏系统稳定性。
// 同时为每个actor分配一个faulty_ptes条目，用于后续faulty页面权限的快速保存/恢复。
int store_orig_host_permissions(void)
{
    ASSERT(sandbox_pteps->util_pteps[0] != NULL, "store_orig_host_permissions");
    ASSERT(sandbox_pteps->data_pteps[0] != NULL, "store_orig_host_permissions");
    ASSERT(sandbox_pteps->code_pteps[0] != NULL, "store_orig_host_permissions");

    static int old_n_actors = 1;
    if (n_actors > old_n_actors) {
        SAFE_FREE(orig_ptes->data_ptes);
        SAFE_FREE(orig_ptes->code_ptes);
        orig_ptes->data_ptes = CHECKED_ZALLOC(N_DATA_PAGES_PER_ACTOR * n_actors * sizeof(pte_t_));
        orig_ptes->code_ptes = CHECKED_ZALLOC(N_CODE_PAGES_PER_ACTOR * n_actors * sizeof(pte_t_));

        SAFE_FREE(faulty_ptes);
        faulty_ptes = CHECKED_ZALLOC(sizeof(pte_t_) * n_actors);
    }
    old_n_actors = n_actors;

    // save the original PTEs for the util pages
    for (int i = 0; i < N_UTIL_PAGES; i++) {
        orig_ptes->util_ptes[i] = *sandbox_pteps->util_pteps[i];
    }

    // save the original PTEs for the code and data pages of the sandbox
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // save the original PTEs for the data pages of the actor
        for (int i = 0; i < N_DATA_PAGES_PER_ACTOR; i++) {
            int page_id = actor_id * N_DATA_PAGES_PER_ACTOR + i;
            orig_ptes->data_ptes[page_id] = *sandbox_pteps->data_pteps[page_id];
        }
        // save the original PTEs for the code pages of the actor
        for (int i = 0; i < N_CODE_PAGES_PER_ACTOR; i++) {
            int page_id = actor_id * N_CODE_PAGES_PER_ACTOR + i;
            orig_ptes->code_ptes[page_id] = *sandbox_pteps->code_pteps[page_id];
        }
    }
    return 0;
}

/// @brief A shortcut to restore the original PTEs for a single page.
/// @param ptep
/// @param old_pte
/// @param vaddr
// 【restore_pte - 恢复单个页面的PTE】
// 作用：将单个页面的PTE恢复为原始值，仅在PTE确实被修改时才执行恢复操作。
// 如果当前PTE值与原始值不同，则写入原始值并刷新TLB(native_page_invalidate)。
// TLB刷新是必要的，因为CPU可能缓存了旧的页表映射，如果不刷新会导致修改不生效。
static void restore_pte(pte_t_ *ptep, pte_t_ old_pte, uint64_t vaddr)
{
    uint64_t curr_pte_val = *(uint64_t *)ptep;
    uint64_t old_pte_val = *(uint64_t *)&old_pte;

    if (curr_pte_val != old_pte_val) {
        *ptep = old_pte;
        native_page_invalidate(vaddr);
    }
}

/// @brief Restore the original PTEs for all sandbox pages.
/// @param void
/// @return
// 【restore_orig_host_permissions - 恢复所有原始权限】
// 作用：遍历所有沙箱页面，将每个页面的PTE恢复为store_orig_host_permissions()保存的原始值。
// 使用场景：fuzzer迭代结束时（需要恢复权限以便下一次迭代重新配置）、模块卸载时。
// 恢复过程中自动刷新TLB，确保CPU使用更新后的映射。
int restore_orig_host_permissions(void)
{
    ASSERT(sandbox_pteps->util_pteps[0] != NULL, "restore_orig_host_permissions");
    ASSERT(sandbox_pteps->data_pteps[0] != NULL, "restore_orig_host_permissions");
    ASSERT(sandbox_pteps->code_pteps[0] != NULL, "restore_orig_host_permissions");

    // restore the original PTEs for the util pages
    for (int i = 0; i < N_UTIL_PAGES; i++) {
        restore_pte(sandbox_pteps->util_pteps[i], orig_ptes->util_ptes[i],
                    (uint64_t)sandbox->util + i * PAGE_SIZE);
    }

    // restore the original PTEs for the code and data pages of the sandbox
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // restore the original PTEs for the data pages of the actor
        for (int i = 0; i < N_DATA_PAGES_PER_ACTOR; i++) {
            int page_id = actor_id * N_DATA_PAGES_PER_ACTOR + i;
            restore_pte(sandbox_pteps->data_pteps[page_id], orig_ptes->data_ptes[page_id],
                        (uint64_t)&sandbox->data[actor_id] + i * PAGE_SIZE);
        }
        // restore the original PTEs for the code pages of the actor
        for (int i = 0; i < N_CODE_PAGES_PER_ACTOR; i++) {
            int page_id = actor_id * N_CODE_PAGES_PER_ACTOR + i;
            restore_pte(sandbox_pteps->code_pteps[page_id], orig_ptes->code_ptes[page_id],
                        (uint64_t)&sandbox->code[actor_id] + i * PAGE_SIZE);
        }
    }
    return 0;
}

/// @brief Configures the page table entries for those sandbox pages that are mapped into
/// user-type actors
/// @param void
/// @return 0 on success, -1 on failure
// 【set_user_pages - 设置用户actor页面权限】
// 作用：为用户态(user)actor所属的沙箱页面设置U/S(User/Supervisor)位，使其可从Ring 3访问。
// 背景：沙箱页面最初由内核(vmalloc)分配，其PTE的U/S位默认为0（仅Supervisor可访问），
//       但用户态actor在Ring 3执行，需要访问这些页面来存储测量结果和执行代码。
// 实现方式：调用set_user_bit()设置PTE的U/S位为1，然后刷新TLB使修改生效。
// 注意：仅修改PL_USER类型的actor的页面，跳过内核态(actor->pl != PL_USER)的actor。
// util页面是所有actor共享的，始终设置U/S位，因为用户actor需要写入测量结果。
int set_user_pages(void)
{
    ASSERT(sandbox_pteps->util_pteps[0] != NULL, "restore_orig_host_permissions");
    ASSERT(sandbox_pteps->data_pteps[0] != NULL, "restore_orig_host_permissions");
    ASSERT(sandbox_pteps->code_pteps[0] != NULL, "restore_orig_host_permissions");

    // enable user access to util pages so that the actors can store measurement results
    for (int i = 0; i < N_UTIL_PAGES; i++) {
        set_user_bit(sandbox_pteps->util_pteps[i]);
        native_page_invalidate((uint64_t)sandbox->util + i * PAGE_SIZE);
    }

    // enable user access to code and data pages of the sandbox that belong to user actors
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // skip non-user actors
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->pl != PL_USER) {
            continue;
        }

        // configure PTEs for each area of the actor sandbox
        for (int i = 0; i < N_DATA_PAGES_PER_ACTOR; i++) {
            int page_id = actor_id * N_DATA_PAGES_PER_ACTOR + i;
            set_user_bit(sandbox_pteps->data_pteps[page_id]);
            native_page_invalidate((uint64_t)&sandbox->data[actor_id] + i * PAGE_SIZE);
        }
        for (int i = 0; i < N_CODE_PAGES_PER_ACTOR; i++) {
            int page_id = actor_id * N_CODE_PAGES_PER_ACTOR + i;
            set_user_bit(sandbox_pteps->code_pteps[page_id]);
            native_page_invalidate((uint64_t)&sandbox->code[actor_id] + i * PAGE_SIZE);
        }
    }

    return 0;
}

/// @brief Fast modification of the faulty page host PTE; sets the permissions according to
/// actor_t->data_permissions
/// @param void
// 【set_faulty_page_host_permissions - 设置faulty页面权限】
// 作用：快速修改每个actor的faulty数据页面的宿主机PTE权限位。
// 这是fuzzer构造侧信道攻击条件的核心操作：
//   - 每个actor有一个专门的faulty页面(FAULTY_PAGE_ID)，其权限在每次fuzzer迭代中动态修改
//   - data_permissions编码了期望的权限位组合（如清除Present位触发#PF，清除Writable位等）
//   - 使用mask_set和mask_clear实现快速位操作：mask_set指定要置1的位，mask_clear指定要置0的位
// 实现细节：
//   1. 先保存当前PTE值到faulty_ptes[]，用于后续恢复
//   2. 从actor->data_permissions提取权限掩码
//   3. MODIFIABLE_PTE_BITS定义了哪些PTE位可以被fuzzer修改（避免破坏关键位）
//   4. 计算新PTE值: pte = (org_value | mask_set) & mask_clear
//   5. 仅在PTE实际改变时才写入和刷新TLB（减少不必要的开销）
void set_faulty_page_host_permissions(void)
{
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        uint64_t pte_mask = actors[actor_id].data_permissions;
        uint64_t mask_set = pte_mask & MODIFIABLE_PTE_BITS;
        uint64_t mask_clear = pte_mask | ~MODIFIABLE_PTE_BITS;

        int page_id = actor_id * N_DATA_PAGES_PER_ACTOR + FAULTY_PAGE_ID;
        pte_t_ *ptep = sandbox_pteps->data_pteps[page_id];
        faulty_ptes[actor_id] = *ptep;
        uint64_t org_value = *(uint64_t *)ptep;
        uint64_t pte = (org_value | mask_set) & mask_clear;
        // PRINT_ERR("set_faulty_page_host_permissions: actor %d, pte 0x%llx -> 0x%llx", actor_id,
        //   org_value, pte);

        if (pte != org_value) {
            *(uint64_t *)ptep = pte;
            native_page_invalidate((uint64_t)&sandbox->data[actor_id] + FAULTY_PAGE_ID * PAGE_SIZE);
        }
    }
}

/// @brief Fast recovery of original permissions of the faulty page host PTE
/// @param void
// 【restore_faulty_page_host_permissions - 恢复faulty页面权限】
// 作用：快速恢复每个actor的faulty页面PTE为set_faulty_page_host_permissions()执行前的值。
// 这是set_faulty_page_host_permissions()的逆操作，使用预先保存的faulty_ptes[]数组。
// 在fuzzer每次迭代结束后调用，确保下一次迭代从原始权限开始重新配置。
// 同样刷新TLB以确保恢复生效。
void restore_faulty_page_host_permissions(void)
{
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        int page_id = actor_id * N_DATA_PAGES_PER_ACTOR + FAULTY_PAGE_ID;
        *sandbox_pteps->data_pteps[page_id] = faulty_ptes[actor_id];
        native_page_invalidate((uint64_t)&sandbox->data[actor_id] + FAULTY_PAGE_ID * PAGE_SIZE);
    }
}

// =================================================================================================
/// @brief Verify get_pte() can walk the kernel page tables for a
/// known-mapped vmalloc VA. Catches a misconfigured kernel pgd base at
/// module-load time rather than crashing inside get_pte() on the first
/// sandbox allocation.
/// @return 0 on success, negative errno on failure
// 【self_test_page_walk - 页表遍历自测试】
// 作用：在模块加载时验证get_pte()能否正确遍历内核页表。
// 原因：如果内核pgd基址配置错误（如ARM64的TTBR1_EL1解码失败），get_pte()会在
//       首次使用时崩溃。自测试在分配沙箱之前就发现并报告问题，避免更严重的后果。
// 方法：分配一个vmalloc页面，调用get_pte()获取其PTE，验证页表遍历能正常工作。
static int self_test_page_walk(void)
{
    void *probe_va = vmalloc(PAGE_SIZE);
    if (!probe_va) {
        PRINT_ERR("self_test_page_walk: probe vmalloc failed\n");
        return -ENOMEM;
    }
    pte_t *probe = get_pte((uint64_t)probe_va);
    vfree(probe_va);
    if (!probe) {
        PRINT_ERR("self_test_page_walk: page-table walk failed\n");
        return -ENODEV;
    }
    return 0;
}

int init_page_table_manager(void)
{
    // 【页表管理器初始化】
    // 步骤：1. 初始化内核pgd基址(ARM64读取TTBR1_EL1) -> 2. 分配PTE保存/缓存结构 -> 3. 自测试
    int err = init_kernel_pgd_base();
    if (err)
        return err;

    orig_ptes = CHECKED_ZALLOC(sizeof(sandbox_ptes_t));
    orig_ptes->data_ptes = CHECKED_ZALLOC(N_DATA_PAGES_PER_ACTOR * sizeof(pte_t_));
    orig_ptes->code_ptes = CHECKED_ZALLOC(N_CODE_PAGES_PER_ACTOR * sizeof(pte_t_));
    orig_ptes->util_ptes = CHECKED_ZALLOC(N_UTIL_PAGES * sizeof(pte_t_));

    sandbox_pteps = CHECKED_ZALLOC(sizeof(sandbox_pteps_t));
    sandbox_pteps->data_pteps = CHECKED_ZALLOC(N_DATA_PAGES_PER_ACTOR * sizeof(pte_t_ *));
    sandbox_pteps->code_pteps = CHECKED_ZALLOC(N_CODE_PAGES_PER_ACTOR * sizeof(pte_t_ *));
    sandbox_pteps->util_pteps = CHECKED_ZALLOC(N_UTIL_PAGES * sizeof(pte_t_ *));

    faulty_ptes = (pte_t_ *)CHECKED_ZALLOC(sizeof(pte_t_));

    err = self_test_page_walk();
    if (err) {
        free_page_table_manager();
        return err;
    }
    return 0;
}

void free_page_table_manager(void)
{
    // Tolerate partial initialization: init_page_table_manager() may have
    // failed mid-way, leaving some pointers NULL
    // 【页表管理器释放】容许部分初始化失败的情况，仅释放非NULL指针。
    // 初始化可能在任意步骤失败，此时部分指针为NULL，必须安全处理。
    if (sandbox_pteps) {
        SAFE_FREE(sandbox_pteps->data_pteps);
        SAFE_FREE(sandbox_pteps->code_pteps);
        SAFE_FREE(sandbox_pteps->util_pteps);
        SAFE_FREE(sandbox_pteps);
    }

    if (orig_ptes) {
        SAFE_FREE(orig_ptes->data_ptes);
        SAFE_FREE(orig_ptes->code_ptes);
        SAFE_FREE(orig_ptes->util_ptes);
        SAFE_FREE(orig_ptes);
    }

    SAFE_FREE(faulty_ptes);
}
