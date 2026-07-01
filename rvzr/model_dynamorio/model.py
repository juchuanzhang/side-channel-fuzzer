"""
文件：基于DynamoRIO的合约模型后端适配器。
该模块实现了将DynamoRIO动态二进制 instrumentation 工具与Revizor侧信道模糊测试框架
对接的适配器类，负责加载测试用例、调用DynamoRIO后端执行追踪、解码追踪结果并返回合约追踪。

DynamoRIO后端通过RCBF/RDBF格式的临时文件与适配器通信，追踪结果以二进制格式输出，
由TraceDecoder解码后转换为框架内部的CTrace格式。

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import os
import tempfile
from subprocess import check_output, CalledProcessError, STDOUT
from typing import List, Tuple, Optional, TYPE_CHECKING, Final, Any
from typing_extensions import TypeAlias

import numpy as np
from numpy.typing import NDArray

from .trace_decoder import TraceDecoder, TraceEntryType, DebugTraceEntryType

from ..model import Model
from ..sandbox import BaseAddrTuple, SandboxLayout, DataArea
from ..traces import CTrace, CTraceEntry
from ..tc_components.test_case_data import save_input_sequence_as_rdbf, InputTaint
from ..config import CONF

if TYPE_CHECKING:
    from ..tc_components.test_case_code import TestCaseProgram
    from ..tc_components.test_case_data import InputData

# DynamoRIO运行命令模板：包含追踪标志、适配器路径和参数格式
_DRRUN_TRACING_FLAGS: Final[str] = " --mode rvzr --instrumented-func test_case_entry "
_ADAPTER_PATH: Final[str] = "~/.local/dynamorio/adapter"
_DRRUN_CMD: Final[str] = "~/.local/dynamorio/drrun -c ~/.local/dynamorio/libdr_model.so " \
    " {flags} -- {binary} {args}"

# 追踪处理相关的常量
_N_REGISTERS_IN_DUMP: Final[int] = 6  # 寄存器数量：rax, rbx, rcx, rdx, rsi, rdi
_BYTES_PER_TAINT_ENTRY: Final[int] = 8  # 每个污点条目对应8字节（uint64大小）
_EOT_MARKER: Final[int] = np.iinfo(np.uint64).max  # 污点文件的传输结束标记（uint64最大值）

# 原始追踪条目的类型别名（来自TraceDecoder的CFFI对象）
# 注意：这些是动态类型的CFFI对象，因此使用Any并附带文档说明
_RawTraceEntry: TypeAlias = Any  # CFFI结构体: trace_entry_t，包含addr、size、type字段
_RawDebugTraceEntry: TypeAlias = Any  # CFFI结构体: debug_trace_entry_t，包含type和regs联合体
_RawTrace: TypeAlias = List[_RawTraceEntry]  # 一次测试执行的追踪条目列表
_RawDebugTrace: TypeAlias = List[_RawDebugTraceEntry]  # 调试追踪条目列表


class DynamoRIOModel(Model):
    """
    DynamoRIO后端适配器类，将DynamoRIO动态二进制 instrumentation 工具
    与Revizor框架的合约模型对接。

    该类负责：
    - 加载测试用例并转换为RCBF格式
    - 构造并执行DynamoRIO命令进行追踪
    - 解码追踪结果并转换为合约追踪格式
    - 支持带污点追踪的执行模式
    """
    _obs_clause_name: Optional[str] = None  # 观测条款名称
    _exec_clause_name: Optional[str] = None  # 执行条款名称

    _installation_checked: bool = False  # 标记是否已检查DynamoRIO安装状态（避免重复检查）

    _test_case: Optional[TestCaseProgram] = None  # 当前加载的测试用例
    _files: _DRFileManager  # 临时文件管理器

    poison_value: int = 0  # 若此值不为0，将在推测性故障加载时返回该值

    # ----------------------------------------------------------------------------------------------
    # 构造函数/析构函数
    def __init__(self,
                 bases: BaseAddrTuple,
                 *args: Any,
                 enable_mismatch_check_mode: bool = False) -> None:
        # 注意：bases参数未使用，因为DynamoRIO后端不允许自定义内存布局
        self._enable_mismatch_check_mode = enable_mismatch_check_mode  # 是否启用不匹配检查模式
        self.is_speculative = True  # 是否启用推测执行，可由configure_clauses修改
        self.poison_value = 0  # 推测性故障加载的返回值，后续可能修改
        self._files = _DRFileManager()  # 创建临时文件管理器

    def __del__(self) -> None:
        """析构函数：删除所有临时文件"""
        self._files.delete_temp_files()

    # ----------------------------------------------------------------------------------------------
    # 公共接口
    def load_test_case(self, test_case: TestCaseProgram) -> None:
        """
        加载测试用例，准备由DynamoRIO后端进行追踪。
        具体操作是将测试用例转换为RCBF二进制格式，以便后端解析。
        :param test_case: 要加载的测试用例对象
        :return: None
        """
        self._test_case = test_case

        # 删除之前的RCBF文件并创建新文件
        self._files.cleanup_on_load_test_case()

        # 将测试用例保存为RCBF格式
        test_case.get_obj().save_rcbf(self._files.rcbf)

    def trace_test_case(self, inputs: List[InputData], nesting: int) -> List[CTrace]:
        """ 使用DynamoRIO后端实现Model.trace_test_case接口，不带污点追踪。 """
        trace = self._trace_test_case_common(inputs, nesting, enable_taints=False)
        self._files.cleanup_after_tracing()
        return trace

    def trace_test_case_with_taints(self, inputs: List[InputData],
                                    nesting: int) -> Tuple[List[CTrace], List[InputTaint]]:
        """ 使用DynamoRIO后端实现Model.trace_test_case_with_taints接口，带污点追踪。 """
        traces = self._trace_test_case_common(inputs, nesting, enable_taints=True)
        assert self._test_case is not None, "Test case must be loaded before tracing"
        taint_reader = _TaintReader(self.layout, self._test_case)
        taints = taint_reader.decode_taints(self._files.taints)
        self._files.cleanup_after_tracing()
        return traces, taints

    def report_coverage(self, path: str) -> None:
        """ 报告覆盖率（尚未实现）"""
        raise NotImplementedError()

    def configure_clauses(self, obs_clause_name: str, exec_clause_name: str) -> None:
        """
        配置后端使用的观测条款和执行条款，并检查条款是否受支持。
        :param obs_clause_name: 观测条款名称
        :param exec_clause_name: 执行条款名称
        :return: None
        :raises: ValueError 如果给定的条款不受支持
        """
        assert self._obs_clause_name is None and self._exec_clause_name is None, \
            "Cannot reconfigure the observation and execution clauses"

        # 确保DynamoRIO后端已安装
        self._check_if_installed()

        # 检查合约是否受支持
        if obs_clause_name not in self.get_supported_obs_clauses(False):
            raise ValueError(f"Unsupported observation clause {obs_clause_name}")
        self._obs_clause_name = obs_clause_name

        if exec_clause_name not in self.get_supported_exec_clauses(False):
            raise ValueError(f"Unsupported execution clause {exec_clause_name}")
        self._exec_clause_name = exec_clause_name

        # 顺序执行条款表示不使用推测执行
        if exec_clause_name in ["seq", "no_speculation"]:
            self.is_speculative = False

    @classmethod
    def get_supported_obs_clauses(cls, check_installation: bool = True) -> List[str]:
        """
        获取支持的观测条款列表。
        :return: 支持的观测条款名称列表
        :raises: FileNotFoundError 如果DynamoRIO后端未安装
        """
        if check_installation:
            cls._check_if_installed()
        cmd = _DRRUN_CMD.format(flags="--list-tracers", binary="echo", args="''")
        output = check_output(cmd, shell=True).decode("utf-8")
        return output.split("\n")[:-1]

    @classmethod
    def get_supported_exec_clauses(cls, check_installation: bool = True) -> List[str]:
        """
        获取支持的执行条款列表。
        :return: 支持的执行条款名称列表
        :raises: FileNotFoundError 如果DynamoRIO后端未安装
        """
        if check_installation:
            cls._check_if_installed()
        cmd = _DRRUN_CMD.format(flags="--list-speculators", binary="echo", args="''")
        output = check_output(cmd, shell=True).decode("utf-8")
        return output.split("\n")[:-1]

    # ----------------------------------------------------------------------------------------------
    # 私有方法
    @classmethod
    def _check_if_installed(cls) -> None:
        """
        检查DynamoRIO后端是否已安装。
        :return: None
        :raises: FileNotFoundError 如果DynamoRIO后端未安装
        """
        if not cls._installation_checked:  # 仅检查一次
            cmd = _DRRUN_CMD.format(flags="--trace-output /dev/null", binary="ls", args="/dev/null")
            try:
                output = check_output(cmd, shell=True, stderr=STDOUT).decode("utf-8")
            except (FileNotFoundError, CalledProcessError):
                output = ""
            if '/dev/null' not in output:
                raise FileNotFoundError(
                    "DynamoRIO backend is not installed\n\n\n"
                    "Please follow the instructions in "
                    "https://microsoft.github.io/side-channel-fuzzer/quick-start/")
            cls._installation_checked = True

    def _trace_test_case_common(self, inputs: List[InputData], nesting: int,
                                enable_taints: bool) -> List[CTrace]:
        """
        在DynamoRIO后端上执行测试用例的通用方法，返回合约追踪和沙箱地址。
        :param inputs: 输入序列
        :param nesting: 模型中模拟的最大嵌套级别
        :param enable_taints: 是否启用污点追踪
        :return: 合约追踪列表，每个输入对应一条追踪
        """
        assert self._test_case is not None, "No test case was loaded"
        if len(inputs) == 0:
            return []

        # 保存输入序列为RDBF格式
        save_input_sequence_as_rdbf(inputs, self._files.rdbf)

        # 调用DynamoRIO后端执行
        cmd = self._construct_drrun_cmd(enable_taints, nesting)
        _ = check_output(cmd, shell=True)

        # 执行可能使用了与之前不同的内存布局，需要更新
        self._update_layout()

        # 从追踪文件读取追踪结果
        reader = _TraceReader(self.layout, self._test_case)
        traces = reader.decode_traces(self._files.traces)
        assert len(traces) > 0, "No traces were retrieved from the DynamoRIO backend"
        assert len(traces) == len(inputs), "Mismatch between the number of inputs and traces"

        if self._enable_mismatch_check_mode:
            # 在此模式下，合约追踪为测试用例结束时的寄存器值
            dbg_reader = _DbgTraceReader(self.layout, self._test_case)
            dbg_traces = dbg_reader.decode_traces(self._files.dbg_traces)
            arch_traces = [CTrace(t.get_typed()[-_N_REGISTERS_IN_DUMP:]) for t in dbg_traces]
            return arch_traces

        return traces

    def _construct_drrun_cmd(self, enable_taints: bool, nesting: int) -> str:
        """
        构造调用DynamoRIO后端的命令字符串。
        根据配置的观测条款、执行条款、嵌套级别等参数组装drrun命令。
        :param enable_taints: 是否启用污点追踪
        :param nesting: 最大推测嵌套级别
        :return: 完整的drrun命令字符串
        """
        flags = _DRRUN_TRACING_FLAGS + \
            f" --tracer {self._obs_clause_name}" + \
            f" --speculator {self._exec_clause_name}" + \
            f" --max-nesting {nesting}" + \
            f" --max-spec-window {CONF.model_max_spec_window}" \
            f" --trace-output {self._files.traces}"
        if enable_taints:
            flags += f" --taint-output {self._files.taints} --enable-taint-tracker"
        if self._enable_mismatch_check_mode:
            flags += f" --log-level 1 --debug-trace-output {self._files.dbg_traces}"
        if self.poison_value != 0:
            flags += f" --poison-value {self.poison_value}"

        binary = _ADAPTER_PATH
        args = f"{self._files.rcbf} {self._files.rdbf} {self._files.layout}"
        cmd = _DRRUN_CMD.format(flags=flags, binary=binary, args=args)
        # print(cmd)
        return cmd

    def _update_layout(self) -> None:
        """
        根据适配器通过bases文件传递的地址更新内存布局。
        读取二进制布局文件中的代码基地址和数据基地址。
        """
        assert self._test_case is not None, "No test case was loaded"
        with open(self._files.layout, 'rb') as f:
            code_base_addr = int.from_bytes(f.read(8), byteorder="little")
            data_base_addr = int.from_bytes(f.read(8), byteorder="little")
        self.layout = SandboxLayout((data_base_addr, code_base_addr), self._test_case.n_actors())


# ==================================================================================================
# 私有类：文件管理
# ==================================================================================================
class _DRFileManager:
    """
    本地类，负责管理DynamoRIO后端使用的临时文件。
    包括RCBF（测试用例二进制）、RDBF（输入数据二进制）、布局文件、
    追踪文件、调试追踪文件和污点追踪文件的创建、清理和删除。
    """

    def __init__(self) -> None:
        self.rcbf: str  # 当前测试用例的RCBF格式临时文件
        self.rdbf: str  # 当前输入序列的RDBF格式临时文件
        self.layout: str  # 接收内存布局的临时文件
        self.traces: str  # 接收合约追踪的临时文件
        self.dbg_traces: str  # 接收调试追踪的临时文件
        self.taints: str  # 接收污点追踪的临时文件
        self._create_temp_files()

    def cleanup_on_load_test_case(self) -> None:
        """ 加载新测试用例时清理RCBF和RDBF文件 """
        with open(self.rcbf, 'wb') as f:
            f.truncate()
        with open(self.rdbf, 'wb') as f:
            f.truncate()

    def cleanup_after_tracing(self) -> None:
        """ 追踪完成后清理适配器输出文件（追踪、调试追踪、污点、布局） """
        with open(self.traces, 'wb') as f:
            f.truncate()
        with open(self.dbg_traces, 'wb') as f:
            f.truncate()
        with open(self.taints, 'wb') as f:
            f.truncate()
        with open(self.layout, 'wb') as f:
            f.truncate()

    def _create_temp_files(self) -> None:
        """ 创建所有需要的临时文件 """
        with tempfile.NamedTemporaryFile("wb", delete=False) as rcbf_f:
            self.rcbf = rcbf_f.name
        with tempfile.NamedTemporaryFile("wb", delete=False) as rdbf_f:
            self.rdbf = rdbf_f.name
        with tempfile.NamedTemporaryFile("wb", delete=False) as trace_f:
            self.traces = trace_f.name
        with tempfile.NamedTemporaryFile("wb", delete=False) as dbg_trace_f:
            self.dbg_traces = dbg_trace_f.name
        with tempfile.NamedTemporaryFile("wb", delete=False) as taint_f:
            self.taints = taint_f.name
        with tempfile.NamedTemporaryFile("wb", delete=False) as bases_f:
            self.layout = bases_f.name

    def delete_temp_files(self) -> None:
        """ 删除所有为DynamoRIO后端创建的临时文件 """
        if os.path.exists(self.rcbf):
            os.unlink(self.rcbf)
        if os.path.exists(self.rdbf):
            os.unlink(self.rdbf)
        if os.path.exists(self.traces):
            os.unlink(self.traces)
        if os.path.exists(self.dbg_traces):
            os.unlink(self.dbg_traces)
        if os.path.exists(self.taints):
            os.unlink(self.taints)
        if os.path.exists(self.layout):
            os.unlink(self.layout)


# ==================================================================================================
# 私有类：追踪解码
# ==================================================================================================
class _TraceReader:
    """
    本地类，负责读取DynamoRIO后端产生的追踪、
    移除无关信息并将其转换为合约模型期望的格式。

    解码流程：
    1. 使用TraceDecoder读取二进制追踪文件
    2. 将原始追踪条目转换为CTraceEntry（内存地址/PC/间接调用）
    3. 修剪与返回指令相关的无关条目
    """

    def __init__(self, layout: SandboxLayout, test_case: TestCaseProgram) -> None:
        self._layout = layout
        self._test_case = test_case
        self._decoder = TraceDecoder()

    def decode_traces(self, trace_path: str) -> List[CTrace]:
        """
        读取DynamoRIO后端产生的追踪并转换为合约模型期望的格式。
        :return: 合约追踪列表
        """
        traces: List[CTrace] = []

        # 遍历二进制追踪并解析条目
        raw_traces: List[_RawTrace] = self._decoder.decode_trace_file(trace_path)
        for raw_trace in raw_traces:
            converted = self._raw_to_ctrace(raw_trace)
            if converted:
                traces.append(converted)

        # 修剪无关条目（如返回指令对应的条目）
        traces = self._trim_traces(traces)

        return traces

    def _raw_to_ctrace(self, raw_trace: _RawTrace) -> CTrace:
        """
        将原始追踪条目转换为合约追踪条目。
        根据条目类型将地址转换为沙箱内的偏移量：
        - 内存读写：转换为数据区偏移
        - PC条目：转换为代码区偏移
        - 间接调用：转换为代码区偏移
        """
        trace: List[CTraceEntry] = []

        for entry in raw_trace:
            type_ = TraceEntryType(entry.type)
            if type_ in (TraceEntryType.ENTRY_READ, TraceEntryType.ENTRY_WRITE):
                val = self._layout.data_addr_to_offset(entry.addr)  # 将数据地址转换为偏移量
                trace.append(CTraceEntry(type_="mem", value=val))
            elif type_ == TraceEntryType.ENTRY_PC:
                val = self._layout.code_addr_to_offset(entry.addr)  # 将代码地址转换为偏移量
                trace.append(CTraceEntry(type_="pc", value=val))
            elif type_ == TraceEntryType.ENTRY_IND:
                val = self._layout.code_addr_to_offset(entry.addr)  # 间接调用的代码偏移量
                trace.append(CTraceEntry(type_="ind", value=val))

        return CTrace(trace)

    def _trim_traces(self, traces: List[CTrace]) -> List[CTrace]:
        """
        修剪追踪中与返回指令相关的无关条目。
        追踪的最后一条指令是返回指令（由模型自动插入，不属于测试用例），
        因此需要移除对应的PC和内存条目。在推测执行中，返回可能发生多次，
        需要移除所有对应的条目。
        :return: 修剪后的追踪列表
        """
        new_traces: List[CTrace] = []
        for trace in traces:
            entry_list = trace.get_typed()

            # 识别属于返回指令的观测条目
            last_mem = None
            last_pc = None
            if entry_list[-1].type_ == "mem":
                last_mem = entry_list[-1].value
                entry_list.pop()
            if entry_list[-1].type_ == "pc":
                last_pc = entry_list[-1].value
                entry_list.pop()

            # 如果返回发生了多次（例如由于推测执行），移除所有对应的条目
            filtered_list = []
            for entry in entry_list:
                if last_pc is not None and entry.type_ == "pc" and entry.value == last_pc:
                    continue
                if last_mem is not None and entry.type_ == "mem" and entry.value == last_mem:
                    continue
                filtered_list.append(entry)

            new_traces.append(CTrace(filtered_list))

        return new_traces


class _DbgTraceReader:
    """
    本地类，负责读取DynamoRIO后端产生的调试追踪。
    调试追踪包含寄存器转储信息，用于不匹配检查模式。
    """

    def __init__(self, layout: SandboxLayout, test_case: TestCaseProgram) -> None:
        self._layout = layout
        self._test_case = test_case
        self._decoder = TraceDecoder()

    def decode_traces(self, dbg_path: str) -> List[CTrace]:
        """
        读取DynamoRIO后端产生的调试追踪并转换为合约模型期望的格式。
        :return: 调试追踪列表
        """
        dbg_traces: List[CTrace] = []

        # 对调试追踪执行同样的解码流程
        raw_dbg_traces: List[_RawDebugTrace] = self._decoder.decode_debug_trace_file(dbg_path)
        for raw_dbg_trace in raw_dbg_traces:
            converted = self._raw_dbg_to_ctrace(raw_dbg_trace)
            if converted:
                dbg_traces.append(converted)

        # 修剪无关条目
        if dbg_traces:
            dbg_traces = self._trim_dbg_traces(dbg_traces)

        return dbg_traces

    def _raw_dbg_to_ctrace(self, raw_dbg_trace: _RawDebugTrace) -> CTrace:
        """
        将原始调试追踪条目转换为合约追踪条目。
        寄存器转 dump 条目包含PC和6个通用寄存器值。
        """
        trace: List[CTraceEntry] = []

        for entry in raw_dbg_trace:
            type_ = DebugTraceEntryType(entry.type)
            if type_ == DebugTraceEntryType.ENTRY_REG_DUMP:
                val = self._layout.code_addr_to_offset(entry.regs.pc)
                trace.append(CTraceEntry(type_="pc", value=val))
                trace.append(CTraceEntry(type_="reg", value=entry.regs.xax))
                trace.append(CTraceEntry(type_="reg", value=entry.regs.xbx))
                trace.append(CTraceEntry(type_="reg", value=entry.regs.xcx))
                trace.append(CTraceEntry(type_="reg", value=entry.regs.xdx))
                trace.append(CTraceEntry(type_="reg", value=entry.regs.xsi))
                trace.append(CTraceEntry(type_="reg", value=entry.regs.xdi))

        return CTrace(trace)

    def _trim_dbg_traces(self, dbg_traces: List[CTrace]) -> List[CTrace]:
        """
        修剪调试追踪中与返回指令相关的条目（与_trim_traces类似，但针对调试追踪）。
        每个寄存器 dump 由1个PC + N个寄存器值组成，需要整体移除。
        """
        # 每个寄存器 dump 包含 1 个PC + 6个寄存器值
        dump_size = 1 + _N_REGISTERS_IN_DUMP

        new_dbg_traces = []
        for dbg_trace in dbg_traces:
            entry_list = dbg_trace.get_typed()

            # 移除最后一个寄存器 dump（对应返回指令）
            last_pc = None
            if entry_list[-dump_size].type_ == "pc":
                last_pc = entry_list[-dump_size].value
                entry_list = entry_list[:-dump_size]

            # 移除所有对应返回指令的寄存器 dump
            filtered_list = []
            skip_count = 0
            for entry in entry_list:
                if skip_count > 0:
                    skip_count -= 1
                    continue
                if last_pc is not None and entry.type_ == "pc" and entry.value == last_pc:
                    skip_count = _N_REGISTERS_IN_DUMP  # 同时跳过寄存器条目
                    continue
                filtered_list.append(entry)

            new_dbg_traces.append(CTrace(filtered_list))

        return new_dbg_traces


# ==================================================================================================
# 私有类：输入污点解码
# ==================================================================================================
class _TaintReader:
    """
    本地类，负责读取DynamoRIO后端产生的输入污点追踪。

    污点输出格式：
    - 输入1：
        [污点值 (8字节)]
        ... 对每个被污染的值重复
        [结束标记 (8字节)]（标记为uint64最大值）
    - 输入2：
        ...
    """

    def __init__(self, layout: SandboxLayout, test_case: TestCaseProgram) -> None:
        self._layout = layout
        self._n_actors = test_case.n_actors()  # 测试用例中的actor数量

    def decode_taints(self, taint_path: str) -> List[InputTaint]:
        """
        读取DynamoRIO后端产生的输入污点并转换为合约模型期望的格式。
        :return: 输入污点列表
        """
        taints: List[InputTaint] = []

        # 为方便处理，将整个文件读入numpy数组
        array: NDArray[np.uint64] = self._file_to_ndarray(taint_path)
        sandbox_end: int = self._layout.data_area_offset(DataArea.OVERFLOW_PAD)  # 沙箱数据区结束偏移

        taint = InputTaint(self._n_actors)
        linear_view = taint.full_linear_view()  # 获取污点数组的线性视图
        unfinished = False
        for entry in array:
            val = int(entry)

            # 到达结束标记？存储当前输入污点并开始新的污点
            if val == _EOT_MARKER:
                taints.append(taint)
                taint = InputTaint(self._n_actors)
                linear_view = taint.full_linear_view()
                unfinished = False
                continue
            unfinished = True

            if val > sandbox_end:
                # 无效的污点值（可能因为某些适配器代码被污染了）
                continue

            # 将污点标记为True（每个条目对应8字节的块）
            linear_view[val // _BYTES_PER_TAINT_ENTRY] = True

        assert not unfinished, "Taint file ended unexpectedly without end marker"
        return taints

    def _file_to_ndarray(self, path: str) -> NDArray[np.uint64]:
        """
        将污点文件读入并转换为numpy数组。
        :return: 包含污点条目的numpy数组（uint64值）
        """
        with open(path, 'rb') as f:
            data = f.read()
        n_entries = len(data) // _BYTES_PER_TAINT_ENTRY  # 计算条目数量
        array = np.frombuffer(data, dtype=np.uint64, count=n_entries)
        return array