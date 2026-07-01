"""
文件：ARM64架构特定的配置选项
本文件定义了ARM64平台上模糊测试框架的配置参数，包括：
1. 各配置选项的有效值范围（Actor属性、指令类别等）
2. 默认处理的异常类型列表
3. 默认指令类别和指令/寄存器黑名单
4. 生成器异常到异常名称的映射
5. Actor的默认配置模板

File: arm64-specific Configuration Options

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List, Dict

# 各配置选项的有效值定义字典
_option_values = {
    # Actor（测试角色）的可用属性字段列表
    'actor': [
        'name',
        'mode',
        'privilege_level',
        'data_properties',
        'data_ept_properties',
        'observer',
        'instruction_blocklist',
        'fault_blocklist',
    ],
    # Actor运行模式：目前仅支持host（主机模式）
    "actor_mode": ['host',],
    # Actor特权级别：目前仅支持kernel（内核模式）
    "actor_privilege_level": ['kernel',],
    # Actor数据页属性的可配置项：控制测试用例数据页的页表属性
    # 包括有效(present)、可写(writable)、用户可访问(user)、已访问(accessed)、
    # 已修改(dirty)、可执行(executable)、保留位(reserved_bit)、随机化(randomized)
    "actor_data_properties": [
        'present',
        'writable',
        'user',
        'accessed',
        'dirty',
        'executable',
        'reserved_bit',
        'randomized',
    ],
    # Actor扩展页表(EPT)数据属性的可配置项
    # 用于虚拟化场景下的二级页表属性控制
    "actor_data_ept_properties": [
        "present",
        "writable",
        "executable",
        "accessed",
        "dirty",
        'reserved_bit',
        'randomized',
    ],
    # Unicorn模拟器支持的指令类别列表
    # 用于Unicorn引擎的指令分类和选择
    'unicorn_instruction_categories': [
        "general-arithmetic",       # 通用算术指令
        "general-barrier",          # 通用屏障指令
        "general-bitwise",          # 通用位运算指令
        "general-uncond_branch",    # 通用无条件分支指令
        "general-cond_branch",      # 通用条件分支指令
        "general-comparison",       # 通用比较指令
        "general-condsel",          # 通用条件选择指令
        "general-dataxfer",         # 通用数据传送指令
        "general-misc",             # 通用杂项指令
    ],
    # DynamoRIO后端支持的指令类别（ARM64上尚未支持DynamoRIO）
    "dr_instruction_categories": [
        # DynamoRIO backend is not yet supported on ARM
    ],
}

# in contrast to x86, on ARM64, we handle all fault types by default
# 与x86不同，ARM64上默认处理所有异常类型
# 异常类型缩写：PF=页故障, DE=调试异常, DB=调试断点,
# BP=断点异常, BR=分支异常, UD=未定义指令异常, GP=通用保护异常
_handled_faults: List[str] = ["PF", "DE", "DB", "BP", "BR", "UD", "PF", "GP"]

# 默认测试的指令类别列表：仅包含算术和数据传送两类基础指令
instruction_categories: List[str] = ["general-arithmetic", "general-dataxfer"]
""" instruction_categories: a default list of tested instruction categories """

# 存在已知bug的指令列表（目前为空，无已知bug指令）
_buggy_instructions: List[str] = []

# 指令黑名单：被排除出模糊测试的指令列表
# 初始为空，随后扩展加入已知bug指令
instruction_blocklist: List[str] = [
]  # yapf: disable
instruction_blocklist.extend(_buggy_instructions)


# 寄存器黑名单：被排除出模糊测试的寄存器列表
# ARM64模糊测试仅使用x0-x5（w0-w5）作为自由寄存器
# 其他寄存器因特殊用途或与插桩代码冲突而被屏蔽：
# x6-x18: 平台保留或调用约定要求的寄存器
# x19-x28: 被框架用作内部状态保存（如x20为Actor基地址）
# x29: 帧指针(FP), x30: 链接寄存器(LR), x31: 零寄存器
# sp: 栈指针，xzr/wzr: 零寄存器（恒为0）
register_blocklist: List[str] = [
    # free - x0 .. x5
    'x6', 'x7', 'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14', 'x15',
    'x16', 'x17', 'x18', 'x19', 'x20', 'x21', 'x22', 'x23',
    'x24', 'x25', 'x26', 'x27', 'x28', 'x29', 'x30', 'x31',
    'sp',
    'w6', 'w7', 'w8', 'w9', 'w10', 'w11', 'w12', 'w13', 'w14', 'w15',
    'w16', 'w17', 'w18', 'w19', 'w20', 'w21', 'w22', 'w23',
    'w24', 'w25', 'w26', 'w27', 'w28', 'w29', 'w30', 'w31',
    'wsp', 'wpc',
    'xzr', 'wzr',
]  # yapf: disable


# FIXME: this is copied from x86, needs to be adapted for ARM64
# 注意：以下映射从x86配置复制而来，需要适配ARM64
# 生成器异常类型到ARM64异常名称的映射
# 将内部使用的异常描述名映射为ARM64架构的异常缩写
_generator_fault_to_fault_name: Dict[str, str] = {
    'div-by-zero': "DE",        # 除零异常 -> 调试异常
    'div-overflow': "DE",       # 除法溢出异常 -> 调试异常
    'opcode-undefined': "UD",   # 未定义操作码 -> 未定义指令异常
    'breakpoint': "BP",         # 断点 -> 断点异常
    'debug-register': "DB",     # 调试寄存器 -> 调试异常
    'non-canonical-access': "GP", # 非规范地址访问 -> 通用保护异常
    'user-to-kernel-access': "PF", # 用户态到内核态访问 -> 页故障
}

# Actor（测试角色）的默认配置模板
# 定义了一个标准测试角色的各项默认属性
_actor_default = {
    'name': "main",              # 角色名称
    'mode': "host",              # 运行模式：主机模式
    'privilege_level': "kernel", # 特权级别：内核态
    'observer': False,           # 是否为观察者角色（非活跃角色）
    'data_properties': {         # 数据页的默认页表属性
        'present': True,         # 页有效
        'writable': True,        # 页可写
        'user': False,           # 非用户可访问（内核专用）
        'accessed': True,        # 已访问标志
        'executable': False,     # 非可执行
        'randomized': False,     # 属性不随机化
    },
    'data_ept_properties': {     # 扩展页表的默认属性
        'present': True,         # 页有效
        'writable': True,        # 页可写
        'executable': False,     # 非可执行
        'accessed': True,        # 已访问标志
        'user': False,           # 非用户可访问
        'randomized': False,     # 属性不随机化
    },
    'instruction_blocklist': set(),  # 指令黑名单（空集合）
    'fault_blocklist': set(),        # 异常黑名单（空集合）
}
