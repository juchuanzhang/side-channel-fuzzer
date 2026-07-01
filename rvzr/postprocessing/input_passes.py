"""
文件：输入数据最小化pass集合——对测试用例的输入数据进行操作。

该模块包含两种输入最小化pass：
1. InputSequenceMinimizationPass：通过迭代移除输入序列中的输入来减少输入数量
2. DifferentialInputMinimizerPass：通过逐步将两个违规输入之间的差异归零来最小化差异

这些pass的目的是在不丢失违规的前提下，尽可能简化输入数据，
使得违规更容易理解和分析。

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import abc
from copy import deepcopy
from math import log2

from typing import TYPE_CHECKING, List, Final, Optional, Tuple

from .pass_abc import BaseMinimizationPass
from ..config import CONF

if TYPE_CHECKING:
    from ..traces import Violation
    from ..tc_components.test_case_code import TestCaseProgram
    from ..tc_components.test_case_data import InputData

_PER_ACTOR_INPUT_SIZE: Final[int] = 0x4000  # 每个actor的输入大小：16 KB
_PRINT_BLOCK_SIZE: Final[int] = 8  # 进度指示器按8字节块打印
_PRINT_LINE_SIZE: Final[int] = 64  # 进度指示器按(64 * 8)字节行打印
_MAX_BLOCK_SIZE: Final[int] = 64  # 尝试一次性归零的最大块大小（64字节）


class BaseInputMinimizationPass(BaseMinimizationPass):
    """ 输入最小化pass的基类，提供公共接口。 """

    @abc.abstractmethod
    def run(self, test_case: TestCaseProgram, org_inputs: List[InputData],
            org_violation: Violation) -> List[InputData]:
        """ 
        执行输入最小化pass的主函数
        :param test_case: 要操作的测试用例对象
        :param org_inputs: 待最小化的输入列表
        :param org_violation: 原始违规对象
        :return: 最小化后的输入列表
        """


class InputSequenceMinimizationPass(BaseInputMinimizationPass):
    """
    输入序列最小化pass——通过迭代移除输入序列中的输入，
    检查违规是否仍然被触发，从而减少输入数量。

    算法分两阶段：
    1. 先通过二分法快速减少输入数量（直到违规不再触发为止）
    2. 再通过逐个移除输入进行精细最小化
    """
    name = "Input Sequence Minimization"

    def run(self, test_case: TestCaseProgram, org_inputs: List[InputData],
            org_violation: Violation) -> List[InputData]:
        """
        执行输入序列最小化。
        :param test_case: 测试用例对象
        :param org_inputs: 原始输入列表
        :param org_violation: 原始违规对象
        :return: 最小化后的违规输入序列
        """
        self._progress.pass_msg("Reducing the number of inputs by halving")
        org_len = len(org_inputs)

        # 第一阶段：二分法快速减少
        violation = org_violation
        nonboosted_inputs = org_inputs
        while len(nonboosted_inputs) > 5:
            new_inputs = nonboosted_inputs[:len(nonboosted_inputs) // 2]  # 取前半部分
            new_violation = self._fuzzer.fuzzing_round(test_case, new_inputs, [])
            if not new_violation:
                break  # 违规不再触发，停止二分
            nonboosted_inputs = new_inputs
            violation = new_violation

        if len(nonboosted_inputs) < org_len:
            self._progress.pass_msg(f"Result: Reduced to {len(nonboosted_inputs)} inputs")
        else:
            self._progress.pass_msg("Result: Could not reduce the number of inputs")

        # 获取增强后的输入并从现在起禁用增强
        inputs = violation.input_sequence
        org_ipc = CONF.inputs_per_class
        CONF.inputs_per_class = 1  # 禁用输入增强

        # 第二阶段：逐个移除输入进行精细最小化
        n_iterations = 10
        self._progress.pass_msg("Reducing the input sequence iteratively")
        for iteration in range(n_iterations):
            self._progress.pass_msg(f"Iteration {iteration + 1}")
            org_len = len(inputs)
            for input_id in range(org_len, 0, -1):  # 从后向前尝试移除每个输入
                new_inputs = inputs[0:input_id] + inputs[input_id + 1:]  # 移除第input_id个输入
                new_violation = self._fuzzer.fuzzing_round(test_case, new_inputs, [])
                if not new_violation:
                    self._progress.next(False)
                    continue  # 移除后违规不再触发，跳过
                self._progress.next(True)
                inputs = new_inputs
                violation = new_violation
            self._progress.pass_finish()
            if len(inputs) == org_len:
                break  # 没有进一步减少，停止迭代
        self._progress.pass_msg(f"Result: Reduced to {len(inputs)} inputs")
        CONF.inputs_per_class = org_ipc  # 恢复原始配置
        return violation.input_sequence


class DifferentialInputMinimizerPass(BaseInputMinimizationPass):
    """
    差异输入最小化pass——通过迭代最小化两个违规输入之间的差异。
    
    算法对每个字节块依次尝试：
    1. 将大块归零并检查违规是否仍触发（逐步减小块大小）
    2. 将单个字节归零
    3. 如果字节已经相等则跳过
    4. 尝试将两个输入的该字节统一
    5. 如果以上都失败，标记该地址为泄露地址

    进度输出符号：.（成功归零）、=（字节已相等）、+（成功统一）、^（泄露地址）
    """
    name = "Differential Input Minimizer"

    _test_case: Optional[TestCaseProgram] = None  # 当前测试用例
    _inputs: Optional[List[InputData]] = None  # 当前输入序列
    _violating_ids: Optional[Tuple[int, int]] = None  # 两个违规输入的ID
    _local_ignore_list: List[int] = []  # 非违规输入ID列表（检查时忽略）
    _leaked_addresses: List[int] = []  # 发现的泄露地址列表

    def run(self, test_case: TestCaseProgram, _: List[InputData],
            org_violation: Violation) -> List[InputData]:
        """
        执行差异输入最小化。
        :param test_case: 测试用例对象
        :param org_violation: 原始违规对象
        :return: 最小化后的输入列表
        """

        # 设置pass的上下文信息
        self._set_pass_context(test_case, org_violation)
        assert self._violating_ids is not None
        self._progress.pass_msg("Minimizing the difference between inputs"
                                f" {self._violating_ids[0]} and {self._violating_ids[1]}")

        # 禁用输入增强，因为我们已经在增强后的输入上操作
        org_conf = (CONF.inputs_per_class,)
        CONF.inputs_per_class = 1

        # 打印进度输出的标题
        print(f'\n{"Address":<11}', end="", flush=True)
        for i in range(0, 64, 8):
            print(f"+0x{i * 8:<6x}", end="", flush=True)

        # 开始处理每个actor
        for actor_id in range(len(CONF.get_actors_conf())):
            self._process_actor(actor_id)
        print("")

        # 打印结果摘要
        self._progress.pass_msg(f"Result: Leaked {len(self._leaked_addresses)} bytes")
        self._progress.pass_msg(f"Addresses: {[hex(addr) for addr in self._leaked_addresses]}")

        # 恢复原始配置
        assert self._inputs is not None
        new_inputs = list(self._inputs)
        CONF.inputs_per_class = org_conf[0]
        self._reset_pass_context()

        return new_inputs

    def _set_pass_context(self, test_case: TestCaseProgram, org_violation: Violation) -> None:
        """
        设置最小化pass的上下文信息。
        :param test_case: 测试用例对象
        :param org_violation: 原始违规对象
        :return: None
        """
        # 存储测试用例和输入
        self._test_case = test_case
        self._inputs = org_violation.input_sequence

        # 存储两个需要最小化的违规输入ID
        violating_input_ids = [i.input_id for i in org_violation.measurements]
        if len(violating_input_ids) > 2:
            violating_input_ids = violating_input_ids[:2]  # 仅取前两个
        self._violating_ids = (violating_input_ids[0], violating_input_ids[1])

        # 存储其他输入ID列表，检查违规时将忽略这些输入
        self._local_ignore_list = [
            i for i in range(len(self._inputs)) if i not in violating_input_ids
        ]

        # 创建泄露地址列表
        self._leaked_addresses = []

    def _reset_pass_context(self) -> None:
        """ 重置最小化pass的上下文信息。 """
        self._test_case = None
        self._inputs = None
        self._local_ignore_list = []
        self._leaked_addresses = []

    def _process_actor(self, actor_id: int) -> None:
        """
        处理单个actor的所有输入区域。
        :param actor_id: actor ID
        """
        assert self._inputs is not None and self._violating_ids is not None

        # 处理actor的所有输入区域
        region_offset = 0
        for region_name in ['main', 'faulty', 'gpr', 'simd']:
            region_size = len(self._inputs[self._violating_ids[0]][actor_id][region_name])

            # 在每个区域内逐块处理所有字节
            i = 0
            while i < region_size:
                absolute_address = actor_id * _PER_ACTOR_INPUT_SIZE + region_offset + i * 8

                # 定期换行和打印空格以提高可读性
                if i % _PRINT_LINE_SIZE == 0:
                    print(f"\n0x{absolute_address:08x} ", end="", flush=True)
                elif i % _PRINT_BLOCK_SIZE == 0:
                    print(" ", end="", flush=True)

                # 处理从当前索引开始的块
                processed_block_size = self._process_block(actor_id, region_name, i, region_size,
                                                           absolute_address)
                i += processed_block_size

            region_offset += region_size * 8  # 更新区域偏移（按8字节单位计算）

    def _process_block(self, actor_id: int, region_name: str, block_start: int, region_size: int,
                       absolute_address: int) -> int:
        """
        尝试最小化两个输入在给定索引处的差异。
        返回处理的块大小（字节数）。
        """
        assert self._test_case is not None and self._inputs is not None \
               and self._violating_ids is not None
        input_a = self._inputs[self._violating_ids[0]]  # 第一个违规输入
        input_b = self._inputs[self._violating_ids[1]]  # 第二个违规输入
        org_input_a = deepcopy(input_a)  # 保存原始值的副本
        org_input_b = deepcopy(input_b)

        def _restore_addr(addr: int) -> None:
            """ 恢复两个输入在指定地址的原始值 """
            input_a[actor_id][region_name][addr] = org_input_a[actor_id][region_name][addr]
            input_b[actor_id][region_name][addr] = org_input_b[actor_id][region_name][addr]

        def _zero_out_block(addr: int) -> int:
            """
            尝试将一块内存归零并检查违规是否仍被触发。
            从最大可能的块大小开始，逐步减小块大小直到违规被触发或块大小为1。
            :return: 成功归零的块大小，或1
            """
            assert input_a is not None and input_b is not None and \
                self._test_case is not None and self._inputs is not None

            # 确定合适的起始块大小，需满足以下条件：
            #    * 块大小不超过512字节（64 * 8）
            block_size: int = _MAX_BLOCK_SIZE - (addr % _MAX_BLOCK_SIZE)
            #    * 块不与下一个区域重叠
            block_size = min(block_size, region_size - addr)
            #    * 块大小为2的幂
            block_size = 2**int(log2(block_size))
            #    * addr mod block_size == 0（地址对齐）
            while block_size > 1 and addr % block_size != 0:
                block_size //= 2

            # 从确定的块大小开始，尝试找到最大的块使得归零后违规仍被触发
            while block_size > 1:
                # 尝试归零该块
                for i in range(block_size):
                    input_a[actor_id][region_name][addr + i] = 0
                    input_b[actor_id][region_name][addr + i] = 0

                # 检查违规是否仍被触发
                if self._check_for_violation(self._test_case, self._inputs,
                                             self._local_ignore_list):
                    # 违规仍触发，成功归零该块；返回
                    return block_size

                # 违规不再触发，恢复原始值并尝试更小的块
                for i in range(block_size):
                    _restore_addr(addr + i)
                block_size //= 2

            # 无法归零大于1字节的块
            return 1

        # 首先，尝试将大块字节归零
        block_size = _zero_out_block(block_start)
        if block_size > 1:
            # 成功归零，打印进度并返回块大小
            n_64byte_blocks = block_size // 8
            n_remainder_bytes = block_size % 8
            if n_remainder_bytes > 0:
                print("." * n_remainder_bytes, end="", flush=True)
                if n_64byte_blocks > 0:
                    print(" ", end="", flush=True)
            if n_64byte_blocks > 0:
                print(("." * 8 + " ") * (n_64byte_blocks - 1), end="", flush=True)
                print("." * 8, end="", flush=True)
            return block_size

        # 尝试归零单个字节
        input_a[actor_id][region_name][block_start] = 0
        input_b[actor_id][region_name][block_start] = 0
        if self._check_for_violation(self._test_case, self._inputs, self._local_ignore_list):
            print(".", end="", flush=True)
            return 1
        _restore_addr(block_start)

        # 检查字节是否已经相等；如果相等，无需进一步处理
        if input_a[actor_id][region_name][block_start] == \
           input_b[actor_id][region_name][block_start]:
            print("=", end="", flush=True)
            return 1

        # 尝试将两个输入的该字节统一（将input_b的值设为input_a的值）
        input_a[actor_id][region_name][block_start] = \
            org_input_a[actor_id][region_name][block_start]
        input_b[actor_id][region_name][block_start] = \
            input_a[actor_id][region_name][block_start]
        if self._check_for_violation(self._test_case, self._inputs, self._local_ignore_list):
            print("+", end="", flush=True)
            return 1
        _restore_addr(block_start)

        # 以上方法都失败，发现了泄露地址
        print("^", end="", flush=True)
        self._leaked_addresses.append(absolute_address)
        return 1