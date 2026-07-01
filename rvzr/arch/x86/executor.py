"""
文件: x86架构执行器(Executor)的实现
File: Implementation of executor for x86 architecture

本模块实现了x86架构的测试用例执行器，负责：
- 在硬件上执行测试用例并收集硬件追踪数据(HTrace)
- 配置内核模块的厂商特定功能（如SSBP补丁、预取器、HPA/GPA碰撞）
- 构建已处理异常(fault)的位图并传递给内核模块
- 区分Intel和AMD厂商的专用执行器

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import Dict, Final

from rvzr.executor import Executor, km_write
from rvzr.config import CONF, ConfigException
from rvzr.target_desc import TargetDesc

# x86异常(fault)标识符到数字ID的映射
# 用于构建已处理异常的位图，每位对应一个异常类型
FAULT_IDS: Final[Dict[str, int]] = {
    'DE': 0,       # 除法错误 (Divide Error)
    'DB': 1,       # 调试异常 (Debug Exception)
    'NMI': 2,      # 不可屏蔽中断 (Non-Maskable Interrupt)
    'BP': 3,       # 断点 (Breakpoint)
    'OF': 4,       # 溢出 (Overflow)
    'BR': 5,       # 范围检查越界 (Bound Range Exceeded)
    'UD': 6,       # 未定义操作码 (Undefined Opcode)
    'NM': 7,       # 设备不可用 (Device Not Available)
    'DF': 8,       # 双重故障 (Double Fault)
    'OLD_MF': 9,   # 协处理器段越界 (Coprocessor Segment Overrun)
    'TS': 10,      # 无效TSS (Invalid TSS)
    'NP': 11,      # 段不存在 (Segment Not Present)
    'SS': 12,      # 栈段故障 (Stack-Segment Fault)
    'GP': 13,      # 一般保护故障 (General Protection Fault)
    'PF': 14,      # 页故障 (Page Fault)
    'SPURIOUS': 15, # 虚假中断 (Spurious Interrupt)
    'MF': 16,      # x87浮点异常 (x87 FPU Floating-Point Error)
    'AC': 17,      # 对齐检查 (Alignment Check)
    'MC': 18,      # 机器检查 (Machine Check)
    'XF': 19,      # SIMD浮点异常 (SIMD Floating-Point Exception)
    'IRET': 32     # IRET返回异常
}


class X86Executor(Executor):
    """
    x86架构的基础执行器类。

    继承自通用Executor，提供x86架构特有的执行器功能：
    - 识别并构建已处理异常的位图
    - 配置内核模块的厂商特定参数（SSBP补丁、预取器开关等）
    """

    def __init__(self, enable_mismatch_check_mode: bool = False):
        """
        初始化x86执行器。

        :param enable_mismatch_check_mode: 是否启用不匹配检查模式
        """
        self._handled_faults_bitmap: int = self._identify_handled_faults()
        super().__init__(enable_mismatch_check_mode)

    def _set_vendor_specific_features(self) -> None:
        """
        设置x86厂商特定的内核模块参数。

        通过写入/sys/rvzr_executor/下的内核模块接口文件来配置：
        - SSBP补丁开关（防止Speculative Store Bypass攻击）
        - 预取器开关（控制CPU预取行为）
        - HPA/GPA碰撞开关（用于测试Foreshadow类漏洞）
        - 已处理异常位图（告知内核模块哪些异常应被捕获）
        """
        km_write("1" if getattr(CONF, 'x86_executor_enable_ssbp_patch') else "0",
                 "/sys/rvzr_executor/enable_ssbp_patch")
        km_write("1" if getattr(CONF, 'x86_executor_enable_prefetcher') else "0",
                 "/sys/rvzr_executor/enable_prefetcher")
        km_write("1" if getattr(CONF, 'x86_enable_hpa_gpa_collisions') else "0",
                 "/sys/rvzr_executor/enable_hpa_gpa_collisions")
        km_write(str(self._handled_faults_bitmap), "/sys/rvzr_executor/handled_faults")

    def _identify_handled_faults(self) -> int:
        """
        根据配置构建已处理异常的位图。

        遍历配置中定义的已处理异常列表，将每个异常的ID对应的位
        设置为1，构建一个整数位图供内核模块使用。

        :return: 已处理异常的位图整数，每一位表示对应异常是否被处理
        """
        handled_faults_bitmap = 0
        for fault in CONF._handled_faults:  # type: ignore  # pylint: disable=protected-access
            if fault in FAULT_IDS:
                handled_faults_bitmap |= (1 << FAULT_IDS[fault])
        return handled_faults_bitmap


class X86IntelExecutor(X86Executor):
    """
    Intel CPU专用的执行器类。

    在初始化时验证当前CPU是否为Intel厂商，若不是则抛出配置异常。
    """

    def __init__(self, enable_mismatch_check_mode: bool = False):
        """
        初始化Intel专用执行器。

        :param enable_mismatch_check_mode: 是否启用不匹配检查模式
        :raises ConfigException: 若当前CPU不是Intel厂商
        """
        super().__init__(enable_mismatch_check_mode)
        self._vendor = TargetDesc.get_vendor()
        if self._vendor != "Intel":
            raise ConfigException(
                "Attempting to run Intel executor on a non-Intel CPUs!\n"
                "Change the `executor` configuration option to the appropriate vendor value.")


class X86AMDExecutor(X86Executor):
    """
    AMD CPU专用的执行器类。

    在初始化时验证当前CPU是否为AMD厂商，若不是则抛出配置异常。
    """

    def __init__(self, enable_mismatch_check_mode: bool = False):
        """
        初始化AMD专用执行器。

        :param enable_mismatch_check_mode: 是否启用不匹配检查模式
        :raises ConfigException: 若当前CPU不是AMD厂商
        """
        super().__init__(enable_mismatch_check_mode)
        self._vendor = TargetDesc.get_vendor()
        if self._vendor != "AMD":
            raise ConfigException(
                "Attempting to run AMD executor on a non-AMD CPUs!\n"
                "Change the `executor` configuration option to the appropriate vendor value.")
