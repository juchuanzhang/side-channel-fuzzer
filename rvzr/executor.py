"""
文件：执行器（Executor）模块
实现与内核模块（kernel module）通信的Python适配器，负责在目标CPU上执行测试用例
并收集对应的硬件迹（hardware traces）。

执行器是模糊测试框架的关键组件之一，其工作流程如下：
1. 将测试用例代码加载到内核模块
2. 将测试用例数据（输入序列）加载到内核模块
3. 调用内核模块执行测量（每条测量重复 n_reps 次）
4. 将测量结果聚合为迹集合（HTrace对象列表）

该模块还包含内核模块配置、输出读取与解析、SMT检测等辅助功能。

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING, List, Tuple, Set, Generator, Optional, Final
from abc import ABC

import sys
import subprocess
import os.path

import numpy as np
import numpy.typing as npt

from rvzr.logs import ExecutorLogger, warning
from rvzr.config import CONF, ConfigException
from rvzr.sandbox import BaseAddrTuple
from rvzr.stats import FuzzingStats
from rvzr.traces import HTrace, RawHTraceSample, HTraceType
from rvzr.tc_components.test_case_data import save_input_sequence_as_rdbf

if TYPE_CHECKING:
    from rvzr.tc_components.test_case_code import TestCaseProgram
    from rvzr.tc_components.test_case_data import InputData

KMOutputLine = Tuple[int, int, int, int, int, int]  # 内核模块输出行的数据类型（6个整数）
ReadingsArray = npt.NDArray[np.void]                  # 原始测量结果的数组类型

STAT = FuzzingStats()


# ==================================================================================================
# 辅助函数
# ==================================================================================================
def km_write(value: str, path: str) -> None:
    """
    向/sys文件系统中的文件写入值，用于配置执行器内核模块。
    :param value: 要写入的值
    :param path: 目标文件路径
    """
    subprocess.run(f"echo -n {value} > {path}", shell=True, check=True)


def _is_smt_enabled() -> bool:
    """
    检查当前CPU是否启用了SMT（超线程/同步多线程）。
    SMT开启时可能导致假阳性（不同超线程共享微架构资源导致干扰）。

    :return: 若SMT启用返回True，否则返回False
    """
    try:
        out = subprocess.run("lscpu", shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError:
        warning("executor", "Could not check if SMT is enabled. Is lscpu installed?")
        return True
    for line in out.stdout.decode().split("\n"):
        if line.startswith("Thread(s) per core:"):
            if line[-1] == "1":
                return False  # 每核只有1个线程 = SMT未启用
            return True       # 每核有多个线程 = SMT已启用
    return True


def _can_set_reserved() -> bool:
    """
    检查当前CPU是否支持设置页表保留位（reserved bits）。
    保留位用于模拟页表故障条件，是侧信道攻击测试的关键特性。

    :return: 若支持设置保留位返回True，否则返回False
    """
    actors_conf = CONF.get_actors_conf()
    reserved_requested = False
    # 检查是否有参与者配置要求设置保留位
    for a in actors_conf:
        if 'reserved_bit' in actors_conf[a]['data_properties'] and \
           actors_conf[a]['data_properties']['reserved_bit']:
            reserved_requested = True
            break
        if 'reserved_bit' in actors_conf[a]['data_ept_properties'] and \
           actors_conf[a]['data_ept_properties']['reserved_bit']:
            reserved_requested = True
            break
    if not reserved_requested:
        return True  # 无需设置保留位，直接返回True

    if CONF.instruction_set == 'arm64':
        return False  # ARM64尚不支持保留位设置

    assert CONF.instruction_set == 'x86-64'
    # 在x86-64上，物理地址位数大于51时无法设置保留位
    physical_bits = int(
        subprocess.run(
            "lscpu | grep 'Address sizes' | awk '{print $3}'",
            shell=True,
            check=True,
            capture_output=True).stdout.decode().strip())
    if physical_bits > 51:
        return False
    return True


def _is_kernel_module_installed() -> bool:
    """检查执行器内核模块是否已安装（通过检测/sys/rvzr_executor/trace文件是否存在）"""
    return os.path.isfile("/sys/rvzr_executor/trace")


def _configure_kernel_module() -> None:
    """配置执行器内核模块的运行参数：预热次数、预执行刷新、测量模式等"""
    km_write(str(CONF.executor_warmups), '/sys/rvzr_executor/warmups')
    km_write("1" if CONF.enable_pre_run_flush else "0", "/sys/rvzr_executor/enable_pre_run_flush")
    km_write(CONF.executor_mode, "/sys/rvzr_executor/measurement_mode")


def _read_trace(n_reps: int,
                n_inputs: int,
                arch_mode: bool = False) -> Generator[Tuple[int, int, KMOutputLine], None, None]:
    """
    生成器函数：读取并解析内核模块的输出。
    处理内核模块的批量输出，逐条返回迹数据。
    迹按逆序读取（内核模块按从最后一个输入到第一个输入的顺序输出）。

    示例：
    假设内核模块对 n_reps=2, n_inputs=2 的输出为：
    ```
    htrace1, pfc0, .., pfc4
    htrace0, pfc0, .., pfc4
    done
    htrace1, pfc0, .., pfc4
    htrace0, pfc0, .., pfc4
    done
    ```
    则生成器将产出以下元组：
    ```
    (0, 1, [htrace1, pfc0, .., pfc4])
    (0, 0, [htrace0, pfc0, .., pfc4])
    (1, 1, [htrace1, pfc0, .., pfc4])
    (1, 0, [htrace0, pfc0, .., pfc4])
    ```

    :param n_reps: 测量重复次数
    :param n_inputs: 输入数量
    :param arch_mode: 若为True，内核模块处于架构模式（输出GPR值而非硬件迹）
    :return: 生成器，产出元组 (重复ID, 输入ID, 迹数据)
    :raises IOError: 若内核模块输出格式异常
    """
    if n_inputs <= 0:
        return

    rep_id = 0
    last_input_id = n_inputs - 1
    while rep_id < n_reps:
        input_id: int = last_input_id  # 从最后一个输入开始（内核模块逆序输出）
        reading_finished: bool = False
        while not reading_finished:
            # 从内核模块读取下一批迹数据
            output = subprocess.check_output(
                f"taskset -c {CONF.executor_taskset} cat /sys/rvzr_executor/trace", shell=True)
            lines = output.decode().split("\n")

            # 解析输出
            for line in lines:
                # 跳过空行
                if not line:
                    continue

                # 遇到"done"表示当前批次结束，继续读取下一批次
                if 'done' in line:
                    reading_finished = True
                    break

                # 将行转换为整数序列
                line_ints = tuple(int(x) for x in line.split(","))

                # 行宽度异常（预期为6个字段）则报错
                if len(line_ints) != 6:
                    warning("executor", f"Unexpected line width: {len(line_ints)}")
                    _rewind_km_output_to_end()
                    raise IOError()

                # 硬件迹为零值表示内核模块执行出错（架构模式下除外）
                if line_ints[0] == 0 and not arch_mode:
                    warning("executor", "Kernel module error; see dmesg for details")
                    _rewind_km_output_to_end()
                    raise IOError()

                # 产出迹数据：(重复ID, 输入ID, 迹数据)
                yield rep_id, input_id, line_ints

                # 移动到下一个输入（逆序遍历）
                input_id -= 1
                if input_id < 0:
                    # 一轮重复的所有输入已读完，重置输入计数器并开始下一轮
                    input_id = last_input_id
                    rep_id += 1
        assert input_id == last_input_id, f"input_id: {input_id}, rep_id: {rep_id}"
    return


def _rewind_km_output_to_end() -> None:
    """
    读取内核模块输出直到遇到'done'行，用于在出错时重置内核模块的输出缓冲区。
    """
    while True:
        output = subprocess.check_output(
            f"taskset -c {CONF.executor_taskset} cat /sys/rvzr_executor/trace", shell=True)
        if 'done' in output.decode():
            break


# ==================================================================================================
# 执行器类：内核模块的Python适配器
# ==================================================================================================
class Executor(ABC):
    """
    执行器接口类：负责在目标CPU上执行测试用例并收集硬件迹。
    
    高层工作流程：
    1. 将测试用例代码加载到内核模块
    2. 将测试用例数据（输入序列）加载到内核模块
    3. 调用内核模块执行测量（每条测量重复 n_reps 次，见 _get_raw_measurements）
    4. 将测量结果聚合为迹集合（见 _aggregate_measurements）
    """

    _curr_test_case: Optional[TestCaseProgram] = None  # 当前加载的测试用例
    _ignore_list: Set[int]                             # 忽略的输入ID集合
    _log: Final[ExecutorLogger]                        # 执行器日志记录器
    _TSC_MASK: Final[np.uint64] = np.uint64(0x0FFFFFFFFFFFFFF0)  # TSC模式的迹掩码（清零低4位）

    _enable_mismatch_check_mode: Final[bool]
    """ mismatch_check_mode: 若为True，执行器将返回GPR值而非硬件迹，
    用于检查模型与执行器之间的架构不一致性 """

    def __init__(self, enable_mismatch_check_mode: bool = False, skip_setup: bool = False):
        """
        初始化执行器，配置内核模块并检查执行环境。
        :param enable_mismatch_check_mode: 若为True，启用架构不一致检查模式
        :param skip_setup: 若为True，跳过内核模块配置（用于特殊场景）
        """
        super().__init__()
        self._enable_mismatch_check_mode = enable_mismatch_check_mode

        self._ignore_list = set()
        self._log = ExecutorLogger()
        if skip_setup:
            warning("executor", "Executor starting without setting up the kernel module")
            return

        # 检查执行环境：
        # SMT开启时可能导致假阳性（超线程间微架构资源共享）
        if _is_smt_enabled() and not enable_mismatch_check_mode:
            warning("executor", "SMT is on! You may experience false positives.")
        # 检查是否支持设置保留位
        if not _can_set_reserved():
            raise ConfigException("Cannot set reserved bits on this CPU")

        # 初始化内核模块
        if not _is_kernel_module_installed():
            print("x86 executor: kernel module not installed\n\n"
                  "Go to https://microsoft.github.io/side-channel-fuzzer/quick-start/ for "
                  "installation instructions.")
            sys.exit(1)
        _configure_kernel_module()
        self._set_vendor_specific_features()

    # ==============================================================================================
    # 公共接口：测试用例加载与迹收集
    # ==============================================================================================
    def load_test_case(self, test_case: TestCaseProgram) -> None:
        """
        将测试用例加载到执行器中。必须在调用 trace_test_case 之前调用此方法。
        
        此方法还会根据配置设置内核模块的不一致检查模式。
        该标志必须在加载测试用例之前设置，因为内核模块根据此标志选择不同的测量函数。

        :param test_case: 要加载的测试用例对象
        """
        # 若需要架构不一致检查模式，在内核模块中启用
        km_write("1" if self._enable_mismatch_check_mode else "0",
                 "/sys/rvzr_executor/enable_dbg_gpr_mode")

        # 将测试用例写入内核模块
        test_case.get_obj().save_rcbf('/sys/rvzr_executor/test_case')
        self._curr_test_case = test_case

        # 重置忽略列表：测试新程序时，旧的忽略列表不再适用
        self._ignore_list = set()

    def trace_test_case(self, inputs: List[InputData], n_reps: int) -> List[HTrace]:
        """
        调用执行器内核模块收集硬件迹。
        对先前加载的测试用例和给定的输入序列执行测量，每个输入重复 n_reps 次。

        :param inputs: 输入列表
        :param n_reps: 每个测量的重复次数
        :return: HTrace对象列表，每个输入对应一个HTrace
        :raises IOError: 若内核模块输出格式异常
        """
        # 空输入列表则直接返回空结果
        if not inputs:
            return []
        n_inputs = len(inputs)

        # 所有输入都被忽略则跳过测量
        if n_inputs <= len(self._ignore_list):
            warning("executor", "All inputs are ignored. Skipping measurements")
            return [HTrace.empty_trace() for _ in range(n_inputs)]

        # 更新统计：记录执行器重复运行次数
        STAT.executor_reruns += n_reps * n_inputs

        # 将输入传输到内核模块
        # 优化：当重复次数为5的倍数或输入数>=1000时，不做输入序列扩展
        # 否则将输入序列扩展5倍以减少内核模块调用次数
        input_sequence = inputs if n_reps % 5 != 0 or n_inputs >= 1000 else inputs * 5
        save_input_sequence_as_rdbf(input_sequence, '/sys/rvzr_executor/inputs')

        # 验证输入传输是否成功
        with open('/sys/rvzr_executor/inputs', 'r') as f:
            if f.readline() != '1\n':
                raise IOError("Error writing inputs to the kernel module")

        # 调用内核模块并读取迹数据
        all_readings: ReadingsArray = np.ndarray(shape=(n_inputs, n_reps), dtype=RawHTraceSample)
        for rep_id, input_id, readings in \
                _read_trace(n_reps, n_inputs, arch_mode=self._enable_mismatch_check_mode):
            all_readings[input_id][rep_id] = readings

        # 后处理：将原始测量结果转换为HTrace对象列表
        traces = self._raw_readings_to_traces(all_readings, n_inputs)
        self._log.dbg_dump_raw_traces(traces)
        return traces

    def _identify_trace_type(self) -> HTraceType:
        """根据配置识别迹类型：架构模式下为'reg'，TSC模式下为'tsc'，否则为'cache'"""
        if self._enable_mismatch_check_mode:
            return "reg"
        if CONF.executor_mode == 'TSC':
            return "tsc"
        return "cache"

    def _raw_readings_to_traces(self, all_readings: ReadingsArray, n_inputs: int) -> List[HTrace]:
        """将原始测量结果转换为HTrace对象，并根据需要进行后处理"""
        traces = []
        trace_type = self._identify_trace_type()
        for input_id in range(n_inputs):
            raw = all_readings[input_id]

            # 架构不一致检查模式不需要后处理
            if self._enable_mismatch_check_mode:
                traces.append(HTrace(raw, trace_type))
                continue

            # 忽略的输入：将迹标记为无效
            if input_id in self._ignore_list:
                traces.append(HTrace.invalid_trace(trace_type))
                continue

            # TSC模式：需要清零迹的低4位（消除时间戳低位噪声）
            if CONF.executor_mode == 'TSC':
                raw['trace'] &= self._TSC_MASK

            traces.append(HTrace(raw, trace_type))
        return traces

    # ==============================================================================================
    # 公共接口：基地址读取
    # ==============================================================================================
    def read_base_addresses(self) -> BaseAddrTuple:
        """
        从执行器内核模块读取两个沙箱区域（数据和代码）的基地址。
        主要用于在执行器和模型之间同步内存布局。

        :return: 包含数据基地址和代码基地址的元组
        """

        with open('/sys/rvzr_executor/print_data_base', 'r') as f:
            data_start = f.readline()
        with open('/sys/rvzr_executor/print_code_base', 'r') as f:
            code_start = f.readline()
        return int(data_start, 16), int(code_start, 16)

    # ==============================================================================================
    # 公共接口：忽略列表管理
    # ==============================================================================================
    def set_ignore_list(self, ignore_list: List[int]) -> None:
        """
        设置执行器应忽略的输入ID列表。
        执行器仍会正常执行这些输入（它们可能用于微架构状态的priming），
        但其硬件迹将被设置为零值，避免假阳性传播。

        :param ignore_list: 要忽略的输入ID列表
        """
        self._ignore_list = set(ignore_list)

    def extend_ignore_list(self, ignore_list: List[int]) -> None:
        """
        向当前忽略列表中追加新的输入ID。
        :param ignore_list: 要追加到忽略列表的输入ID列表
        """
        self._ignore_list.update(ignore_list)

    # ==============================================================================================
    # 公共接口：快速模式
    # ==============================================================================================
    def set_quick_and_dirty(self, state: bool) -> None:
        """
        启用或禁用执行器的快速模式（quick and dirty mode）。
        在此模式下，执行器将跳过部分稳定化阶段，使测量更快但可靠性降低。

        :param state: True启用快速模式，False禁用
        """
        km_write("1" if state else "0", "/sys/rvzr_executor/enable_quick_and_dirty_mode")

    # ==============================================================================================
    # 私有接口：厂商特定特性设置
    # ==============================================================================================
    def _set_vendor_specific_features(self) -> None:
        """在内核模块中设置CPU厂商特定的特性（由架构子类实现）"""
