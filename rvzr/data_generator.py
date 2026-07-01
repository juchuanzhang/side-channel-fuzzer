"""
File: Input Generation.

      An input is a sequence of bytes that is used to initialize memory and registers in
      the model or executor before running a test case program. The input generator
      is responsible for generating random inputs for the test cases.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT

文件用途：测试用例输入数据生成器。
输入是一组字节序列，用于在模型或执行器运行测试用例程序之前初始化内存和寄存器。
本模块负责为测试用例生成随机输入数据，并支持"boosting"机制——基于污点信息生成
与原始输入产生相同合约追踪的新输入。
"""
import os
import random
from typing import List, Tuple, Final

import numpy as np

from .tc_components.test_case_data import InputData, InputTaint
from .config import CONF
from .logs import inform

# 32位整数最大值，用于状态和种子计算
POW32 = pow(2, 32)


class DataGenerator:
    """
    Class responsible for generating random inputs for test cases.

    测试用例输入数据生成器类。
    负责生成随机输入、基于污点信息的boosted输入，以及从文件加载输入。
    使用种子控制随机数生成，确保可复现性。
    """

    _state: int = 0  # 当前生成器状态（种子值）
    _boosting_state: int = 0  # boosting操作前的状态备份，用于确保幂等性
    _max_gpr_value: Final[int] = pow(2, 64) - 1  # 64位通用寄存器最大值

    def __init__(self, seed: int):
        """
        初始化输入数据生成器。

        :param seed: 初始种子值，0表示使用随机种子
        """
        # 最大输入值，由配置中的熵位数决定
        self.max_input_value = pow(2, CONF.data_generator_entropy_bits)
        self._state = seed

        # 控制是否生成特殊值（零值和最大值）
        self._skip_special_values = CONF.input_gen_probability_of_special_value == 0
        # 零值概率：直接使用配置中的特殊值概率
        self._probability_of_zero = CONF.input_gen_probability_of_special_value
        # 最大值概率：特殊值概率的两倍（在随机抽取时，落在零值和最大值之间的区间即为最大值）
        self._probability_of_max = CONF.input_gen_probability_of_special_value * 2
        assert self._probability_of_max < 1, \
            "The sum of probabilities of special values must be less than 1."

    def get_state(self) -> int:
        """
        Return the current state of the generator.
        State is the seed value that will be used to generate the next input.

        返回当前生成器状态（即下一个输入将使用的种子值）。
        """
        return self._state

    def _reset_boosting_state(self) -> None:
        """
        Reset the state (i.e., seed) of the generator to the last state before boosting

        将生成器状态重置为boosting操作前的状态，确保多次调用generate_boosted
        产生相同结果（幂等性）。
        """
        self._boosting_state = self._state

    def generate(self, count: int, n_actors: int) -> List[InputData]:
        """
        Generate a list of random inputs.
        :param count: The number of inputs to generate
        :return: A list of generated inputs

        生成指定数量的随机输入数据。

        :param count: 要生成的输入数量
        :param n_actors: 参与者（actor）数量，每个输入包含n_actors个参与者的数据
        :return: 生成的输入数据列表
        """
        # 首次调用且种子为0时，使用随机种子
        if self._state == 0:
            self._state = random.randint(0, pow(2, 32) - 1)
            inform("data_gen", f"Setting input seed to: {self._state}")

        generated_inputs = []
        for _ in range(count):
            # 每次生成一个输入，并更新状态种子
            input_, self._state = self._generate_one(self._state, n_actors)
            generated_inputs.append(input_)

        # 保存boosting前的状态，确保后续boosting操作从更新后的状态继续
        self._boosting_state = self._state
        return generated_inputs

    def generate_boosted(self, inputs: List[InputData], taints: List[InputTaint],
                         inputs_per_class: int) -> List[InputData]:
        """
        Extend the given input sequence with new inputs such that the new inputs should produce
        the same contract traces as the original inputs. This achieved by copying the original
        inputs and modifying them based on the taints collected by the model while tracing the
        test case with the original inputs (i.e, non-tainted values are replaced with random values,
        and the tainted values are copied).

        For example, if the original inputs are [A, B, C] and inputs_per_class=3,
        then the new sequence will be [A, B, C, A', B', C', A'', B'', C''],
        where A, A', and A'' produce the same contract traces, and so on.

        NOTE: The function is idempotent, i.e., calling it multiple times with the same inputs
        and taints will produce the same sequence of new inputs. This is because the state of the
        generator is reset to the last state before boosting every time the function is called.

        基于污点信息扩展输入序列，生成与原始输入产生相同合约追踪的新输入。
        实现方式：复制原始输入，非污点值替换为随机值，污点值保留原始值。
        这样可以确保新输入与原始输入走相同的合约追踪路径。

        例如：原始输入为[A, B, C]，inputs_per_class=3，
        则结果为[A, B, C, A', B', C', A'', B'', C'']，
        其中A、A'、A''产生相同的合约追踪。

        注意：此函数是幂等的——每次调用都会重置boosting状态，
        因此相同输入和污点多次调用产生相同结果。

        :param inputs: 原始输入序列
        :param taints: 对应的污点信息序列，标记哪些值影响合约追踪
        :param inputs_per_class: 每个等价类中的输入数量（包括原始输入）
        :return: 扩展后的输入序列
        """
        if not inputs:
            return []
        assert len(inputs) == len(taints), "Error: Cannot extend inputs. The number of taints" \
                                           " does not match the number of inputs."
        n_actors = len(inputs[0])
        input_size = InputData.n_data_entries_per_actor()

        # 重置boosting状态以确保幂等性
        self._reset_boosting_state()
        boosted_inputs = list(inputs)  # make a copy
        for _ in range(inputs_per_class - 1):
            for i, input_ in enumerate(inputs):
                # Generate new, fully random input
                # 生成一个全新的随机输入
                new_input, self._boosting_state = self._generate_one(self._boosting_state, n_actors)

                # Copy tainted values from the original input
                # 将原始输入中的污点值复制到新输入中，非污点值保持随机
                for actor_id in range(n_actors):
                    taint = taints[i].linear_view(actor_id)
                    input_old = input_.linear_view(actor_id)
                    input_new = new_input.linear_view(actor_id)
                    for j in range(input_size):
                        if taint[j]:
                            # 污点标记的值从原始输入复制，确保合约追踪不变
                            input_new[j] = input_old[j]

                # Add the new input to the sequence
                boosted_inputs.append(new_input)
        return boosted_inputs

    def load(self, input_paths: List[str]) -> List[InputData]:
        """
        Load a sequence of inputs from a directory with binary inputs.

        从二进制文件加载输入序列。
        用于复现违规场景，需要生成器状态与模糊测试时一致。

        :param input_paths: 输入文件路径列表
        :return: 加载的输入数据列表
        """
        # 与generate()保持一致的状态更新逻辑，确保复现违规时状态一致
        if self._state == 0:
            self._state = random.randint(0, pow(2, 32) - 1)
            inform("data_gen", f"Setting input seed to: {self._state}")

        inputs = []
        n_actors = len(CONF.get_actors_conf())
        for input_path in input_paths:
            input_ = InputData(n_actors)

            # check that the file is not corrupted
            # 检查文件大小是否正确
            size = os.path.getsize(input_path)
            expected = input_.itemsize * n_actors
            if size != expected:
                raise ValueError(f"Incorrect size of input `{input_path}` "
                                 f"({size} B, expected {expected} B)")

            input_.load(input_path)
            inputs.append(input_)
            # 每加载一个输入就递增状态，与generate的行为保持一致
            self._state += 1

        self._boosting_state = self._state
        return inputs

    def _generate_one(self, state: int, n_actors: int) -> Tuple[InputData, int]:
        """
        生成单个输入数据。

        :param state: 当前种子值
        :param n_actors: 参与者数量
        :return: (生成的输入数据, 下一个种子值)
        """
        input_ = InputData(n_actors)
        input_.seed = state

        per_actor_data_size = input_.itemsize // 8
        n_registers = input_[0]['gpr'].itemsize

        # 使用numpy的随机数生成器，基于种子确保可复现性
        rng = np.random.default_rng(seed=state)
        for i in range(n_actors):
            # generate random data
            # 生成随机数据，每个元素为64位无符号整数
            data = rng.integers(
                self.max_input_value, size=per_actor_data_size, dtype=np.uint64)  # type: ignore

            # copy lower 32-bits to upper 32-bits, for every 8-byte word
            # 将低32位复制到高32位，使每个8字节word的低32位和高32位相同
            # 这是为了确保寄存器值在32位和64位视角下一致
            data = (data << np.uint64(32)) + data

            # for each of the registers and with a probability of 0.01
            # set the register to zero or to max value
            # 以一定概率将寄存器设为零值或最大值，测试边界条件
            if not self._skip_special_values:
                for reg_id in range(n_registers):
                    roll = rng.random()
                    if roll < self._probability_of_zero:
                        # 设为零值
                        input_[i]['gpr'][reg_id] = 0
                    elif roll < self._probability_of_max:
                        # 设为64位最大值
                        input_[i]['gpr'][reg_id] = self._max_gpr_value

            input_.set_actor_data(i, data)

        # 返回输入数据和下一个种子值（递增1）
        return input_, state + 1
