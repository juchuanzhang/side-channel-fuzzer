"""
文件: x86架构特定的配置选项
File: x86-specific Configuration Options

本模块定义了x86架构模糊测试框架的所有配置选项，包括：
- Actor（执行角色）的属性选项：名称、模式、特权级、数据属性等
- Unicorn和DynamoRIO后端支持的指令类别列表
- 执行器配置：预取器、SSBP补丁、HPA/GPA碰撞等
- 指令阻止列表(instruction_blocklist)：禁止生成的指令
- 寄存器阻止列表(register_blocklist)：禁止使用的寄存器
- 已知问题指令列表(_buggy_instructions)：已知会产生误报的指令
- 异常(fault)类型映射和Actor默认配置

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List

# 配置选项的有效值定义
# 每个配置项对应一个允许值列表，用于配置验证
_option_values = {
    # Actor属性：定义执行角色的可配置属性名
    'actor': [
        'name',             # 角色名称
        'mode',             # 执行模式（host/guest）
        'privilege_level',  # 特权级别（kernel/user）
        'data_properties',  # 数据页属性配置
        'data_ept_properties',  # EPT数据页属性配置
        'observer',         # 是否为观察者角色
        'instruction_blocklist',  # 角色级指令阻止列表
        'fault_blocklist',  # 角色级异常阻止列表
    ],
    # Actor执行模式选项
    "actor_mode": [
        'host',   # 主机模式（在宿主机上执行）
        'guest',  # 客户机模式（在虚拟机内执行）
    ],
    # Actor特权级别选项
    "actor_privilege_level": [
        'kernel',  # 内核特权级
        'user',    # 用户特权级
    ],
    # Actor数据页属性选项：定义数据内存页的可配置PTE属性
    "actor_data_properties": [
        'present',         # 页是否存在
        'writable',        # 页是否可写
        'user',            # 页是否可被用户态访问
        'write-through',   # 写穿透缓存模式
        'cache-disable',   # 禁用缓存
        'accessed',        # 已访问标志
        'dirty',           # 已修改标志
        'executable',      # 页是否可执行
        'reserved_bit',    # 保留位（用于测试PTE保留位触发异常）
        'randomized',      # 属性是否随机化
    ],
    # Actor EPT数据页属性选项：定义EPT中数据内存页的可配置属性
    "actor_data_ept_properties": [
        "present",
        "writable",
        "executable",
        "accessed",
        "dirty",
        'reserved_bit',
        'randomized',
    ],
    # Unicorn模拟器后端支持的指令类别列表
    # 这些指令类别可以在Unicorn模拟器中正确执行
    'unicorn_instruction_categories': [
        # 基础x86 - 用户指令
        "BASE-BINARY",
        "BASE-BITBYTE",
        "BASE-CMOV",
        "BASE-COND_BR",
        "BASE-CONVERT",
        "BASE-DATAXFER",
        "BASE-FLAGOP",
        "BASE-LOGICAL",
        "BASE-MISC",
        "BASE-NOP",
        "BASE-POP",
        "BASE-PUSH",
        "BASE-SEMAPHORE",
        "BASE-SETCC",
        "BASE-STRINGOP",
        "BASE-WIDENOP",

        # 基础x86 - 系统指令
        "BASE-INTERRUPT",
        # 以下指令类别因Unicorn已知bug或不支持而注释掉:
        # "BASE-ROTATE",      # Unicorn未知bug - 模拟不正确
        # "BASE-SHIFT",       # Unicorn未知bug - 模拟不正确
        # "BASE-UNCOND_BR",   # 不支持：复杂控制流
        # "BASE-CALL",        # 不支持：复杂控制流
        # "BASE-RET",         # 不支持：复杂控制流
        # "BASE-SEGOP",       # 不支持：系统指令
        # "BASE-IO",          # 不支持：系统指令
        # "BASE-IOSTRINGOP",  # 不支持：系统指令
        # "BASE-SYSCALL",     # 不支持：系统指令
        # "BASE-SYSRET",      # 不支持：系统指令
        "BASE-SYSTEM",
        "LONGMODE-CONVERT",
        "LONGMODE-DATAXFER",
        "LONGMODE-SEMAPHORE",
        "LONGMODE-SYSCALL",
        "LONGMODE-SYSRET",

        # SIMD扩展指令
        "SSE-SSE",
        "SSE-DATAXFER",
        "SSE-MISC",
        "SSE-LOGICAL_FP",
        # "SSE-CONVERT",  # 需要MMX支持
        # "SSE-PREFETCH",  # 预取指令在Unicorn中不触发内存访问
        "SSE2-SSE",
        "SSE2-DATAXFER",
        "SSE2-MISC",
        "SSE2-LOGICAL_FP",
        "SSE2-LOGICAL",
        # "SSE2-CONVERT",  # 需要MMX支持
        # "SSE2-MMX",   # 需要MMX支持
        "SSE3-SSE",
        "SSE3-DATAXFER",
        # "SSE4-SSE",  # 尚未测试
        "SSE4-LOGICAL",
        "SSE4a-BITBYTE",
        "SSE4a-DATAXFER",

        # 其他指令
        "CLFLUSHOPT-CLFLUSHOPT",
        "CLFSH-MISC",
        # "MPX-MPX",  # 已不再支持
        "SMX-SYSTEM",
        "VTX-VTX",
        "XSAVE-XSAVE",
    ],
    # DynamoRIO后端支持的指令类别列表
    # 支持比Unicorn更多的指令类别，包括AVX、BMI、AES等扩展
    "dr_instruction_categories": [
        # 基础x86 - 用户指令
        "BASE-BINARY",
        "BASE-BITBYTE",
        "BASE-CMOV",
        "BASE-COND_BR",
        "BASE-CONVERT",
        "BASE-DATAXFER",
        "BASE-FLAGOP",
        "BASE-LOGICAL",
        "BASE-MISC",
        "BASE-NOP",
        "BASE-POP",
        "BASE-PUSH",
        "BASE-SEMAPHORE",
        "BASE-SETCC",
        "BASE-STRINGOP",
        "BASE-WIDENOP",

        # 基础x86 - 系统指令
        "BASE-INTERRUPT",
        "BASE-ROTATE",
        "BASE-SHIFT",
        # 以下因复杂控制流或系统指令不支持而注释掉:
        # "BASE-UNCOND_BR",   # 不支持：复杂控制流
        # "BASE-CALL",        # 不支持：复杂控制流
        # "BASE-RET",         # 不支持：复杂控制流
        # "BASE-SEGOP",       # 不支持：系统指令
        # "BASE-IO",          # 不支持：系统指令
        # "BASE-IOSTRINGOP",  # 不支持：系统指令
        # "BASE-SYSCALL",     # 不支持：系统指令
        # "BASE-SYSRET",      # 不支持：系统指令
        "BASE-SYSTEM",
        "LONGMODE-CONVERT",
        "LONGMODE-DATAXFER",
        "LONGMODE-SEMAPHORE",
        "LONGMODE-SYSCALL",
        "LONGMODE-SYSRET",

        # 以下为DynamoRIO额外支持的扩展指令类别
        "3DNOW_PREFETCH-PREFETCH",
        "ADOX_ADCX-ADOX_ADCX",
        "BASE-BINARY",
        "BASE-BITBYTE",
        "BASE-CMOV",
        "BASE-COND_BR",
        "BASE-CONVERT",
        "BASE-DATAXFER",
        "BASE-FLAGOP",
        "BASE-LOGICAL",
        "BASE-MISC",
        "BASE-NOP",
        "BASE-POP",
        "BASE-ROTATE",
        "BASE-SEMAPHORE",
        "BASE-SETCC",
        "BASE-SHIFT",
        "BASE-WIDENOP",
        "LONGMODE-CONVERT",
        "LONGMODE-DATAXFER",
        "LONGMODE-POP",
        "LONGMODE-PUSH",
        "LONGMODE-SEMAPHORE",
        "MMX-MMX",
        "MMX-LOGICAL",
        "MMX-DATAXFER",
        "SSE2-MMX",
        "SSE3-MMX",
        "SSSE3-MMX",
        "SSE-CONVERT",
        "SSE-DATAXFER",
        "SSE-MISC",
        "SSE-PREFETCH",
        "SSE-SSE",
        "SSE2-CONVERT",
        "SSE2-DATAXFER",
        "SSE2-LOGICAL",
        "SSE2-MISC",
        "SSE2-SSE",
        "SSE3-DATAXFER",
        "SSE3-SSE",
        "SSSE3-SSE",
        "SSE4-LOGICAL",
        "SSE4-SSE",
        "AVX-AVX",
        "AVX-BROADCAST",
        "AVX-DATAXFER",
        "AVX-LOGICAL",
        "AVX-STTNI",
        "AVX2-AVX2",
        "AVX2-BROADCAST",
        "AVX2-DATAXFER",
        "AVX2-LOGICAL",
        "AES-AES",
        "AVXAES-AES",
        "BMI1-BMI1",
        "BMI2-BMI2",
        "MOVBE-DATAXFER",
        "LZCNT-LZCNT",
        "PCLMULQDQ-PCLMULQDQ",
    ],
}

# 默认情况下，始终处理页故障(PF)
_handled_faults: List[str] = ["PF"]

# x86执行器配置选项
x86_executor_enable_prefetcher: bool = False
""" x86_executor_enable_prefetcher: 启用所有预取器"""
x86_executor_enable_ssbp_patch: bool = True
""" x86_executor_enable_ssbp_patch: 启用Speculative Store Bypass防护补丁"""
x86_enable_hpa_gpa_collisions: bool = False
""" x86_enable_hpa_gpa_collisions: 启用HPA和GPA之间的碰撞；
用于测试Foreshadow类泄漏漏洞"""
x86_disable_div64: bool = True
""" x86_disable_div64: 不生成64位除法指令 """
x86_generator_align_locks: bool = True
""" x86_generator_align_locks: 将所有生成的lock指令对齐到8字节边界 """

# 默认测试的指令类别列表
instruction_categories: List[str] = ["BASE-BINARY", "BASE-BITBYTE", "BASE-COND_BR"]
""" instruction_categories: 默认的测试指令类别列表 """

# 已知存在问题的指令列表
# 这些指令在Unicorn模拟器中存在已知缺陷或会产生误报
_buggy_instructions: List[str] = [
    "sti",  # 启用中断
    "cli",  # 禁用中断；以防万一被阻止
    "xlat",  # 需要段寄存器支持
    "xlatb",  # 需要段寄存器支持
    "cmpxchg8b",  # 已知bug：不执行内存访问钩子
    "lock cmpxchg8b",  # https://github.com/unicorn-engine/unicorn/issues/990
    "cmpxchg16b",  # 已知bug：不执行内存访问钩子
    "lock cmpxchg16b",  # https://github.com/unicorn-engine/unicorn/issues/990
    "cpuid",  # 产生误报：模拟器和CPU的返回值很可能不同
    "cmpps",  # 导致崩溃
    "cmpss",  # 导致崩溃
    'cmppd',  # 导致崩溃
    'cmpsd',  # 导致崩溃
    'movq2dq',
    'movdq2q',
    'rcpps',  # 模拟不正确
    'rcpss',  # 模拟不正确
    #
    'pcmpestriq',  # 冲突的操作数大小修饰符
    'pcmpestrmq',  # 冲突的操作数大小修饰符
    'vpcmpestriq',  # 冲突的操作数大小修饰符
    'vpcmpestrmq',  # 冲突的操作数大小修饰符
    #
    'maskmovdqu',  # 非临时存储
    'maskmovq',  # 非临时存储
    'vmaskmovdqu',  # 非临时存储
    'vmaskmovq',  # 非临时存储
]

# 指令阻止列表：这些指令不会被模糊测试器生成
instruction_blocklist: List[str] = [
    # 难以修复的问题：
    # - 需要复杂的插桩
    "enterw", "enter", "leavew", "leave",
    # - 需要支持所有可能的中断
    "int",
    # - 系统管理指令
    "encls", "vmxon", "stgi", "skinit", "ldmxcsr", "stmxcsr",

    # - 不支持的指令（fence类指令由框架内部使用）
    "lfence", "mfence", "sfence", "clflush", "clflushopt",

    # - 正在开发中的指令
    # -- 触发FPVI（尚未有约定和插桩）
    "divps", "divss", 'divpd', 'divsd',
    "mulss", "mulps", 'mulpd', 'mulsd',
    "rsqrtps", "rsqrtss", "sqrtps", "sqrtss", 'sqrtpd', 'sqrtsd',
    'addps', 'addss', 'addpd', 'addsd',
    'subps', 'subss', 'subpd', 'subsd',
    'addsubpd', 'addsubps', 'haddpd', 'haddps', 'hsubpd', 'hsubps',
]  # yapf: disable
instruction_blocklist.extend(_buggy_instructions)

# 寄存器阻止列表：这些寄存器不会被测试用例使用
# x86执行器内部使用R8...R15、RSP、RBP，因此被排除
# 段寄存器也被排除，因为目前不支持段寄存器处理
# CR*和DR*控制/调试寄存器同样被排除
register_blocklist: List[str] = [
    # 可用寄存器 - rax, rbx, rcx, rdx, rdi, rsi
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rsp', 'rbp',
    'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d', 'esp', 'ebp',
    'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w', 'sp', 'bp',
    'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b', 'spl', 'bpl',
    'es', 'cs', 'ss', 'ds', 'fs', 'gs',  # 段寄存器
    'cr0', 'cr2', 'cr3', 'cr4', 'cr8',   # 控制寄存器
    'dr0', 'dr1', 'dr2', 'dr3', 'dr4', 'dr5', 'dr6', 'dr7',  # 调试寄存器
    "xcr0", "gdtr", "ldtr", "idtr", "tr", "fsbase", "gsbase", "msrs", "x87control", "tsc", "tscaux",
    "mxcsr",

    # XMM8-15在Unicorn中存在问题
    "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
    "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15",
]  # yapf: disable


# 模糊测试器异常名到x86异常标识符的映射
# 用于将配置中的异常类型转换为x86异常编号
_generator_fault_to_fault_name = {
    'div-by-zero': "DE",           # 除零错误 -> DE (Divide Error)
    'div-overflow': "DE",          # 除法溢出 -> DE
    'opcode-undefined': "UD",     # 未定义操作码 -> UD
    'breakpoint': "BP",            # 断点 -> BP
    'debug-register': "DB",        # 调试寄存器 -> DB
    'non-canonical-access': "GP", # 非规范地址访问 -> GP
    'user-to-kernel-access': "PF", # 用户态访问内核内存 -> PF
    'page-fault': "PF"             # 页故障 -> PF
}

# Actor默认配置模板
# 定义了新创建Actor的默认属性值
_actor_default = {
    'name': "main",                 # 默认角色名
    'mode': "host",                 # 默认在宿主机执行
    'privilege_level': "kernel",    # 默认内核特权级
    'observer': False,              # 默认不是观察者
    'data_properties': {            # 默认数据页属性
        'present': True,
        'writable': True,
        'user': False,
        'write-through': False,
        'cache-disable': False,
        'accessed': True,
        'dirty': True,
        'executable': False,
        'reserved_bit': False,
        'randomized': False,
    },
    'data_ept_properties': {        # 默认EPT数据页属性
        'present': True,
        'writable': True,
        'executable': False,
        'accessed': True,
        'dirty': True,
        'user': False,
        'reserved_bit': False,
        'randomized': False,
    },
    'instruction_blocklist': set(),  # 默认空指令阻止列表
    'fault_blocklist': set(),        # 默认空异常阻止列表
}
