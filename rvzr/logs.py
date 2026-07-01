"""
文件：全局日志基础设施 - 为所有 Revizor 模块提供日志与调试输出服务

本模块实现了侧信道模糊测试框架的日志系统，包括：
- _LoggingConfig：基于 Borg 模式的全局日志配置管理类
- 基础日志函数：error、warning、inform、dbg
- FuzzLogger：模糊测试器专用日志类（进度条、阶段报告、违规报告）
- ModelLogger：合约模型专用日志类（指令追踪、内存访问、推测回滚、异常）
- GeneratorLogger：程序生成器专用日志类（指令池调试输出）
- ExecutorLogger：执行器专用日志类（原始追踪输出）
- ISALogger：ISA 规范专用日志类（指令过滤原因输出）

所有日志类通过 _LoggingConfig 共享日志模式配置，支持彩色输出和
多行/单行重绘两种显示模式。

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import sys
from datetime import datetime
from typing import TYPE_CHECKING, NoReturn, Dict, List, Optional, Set, Any, Final, Tuple
from pprint import pformat
from traceback import print_stack

from .config import CONF
from .stats import FuzzingStats

if TYPE_CHECKING:
    from .model import Model
    from .sandbox import SandboxLayout
    from .model_unicorn.execution_context import ModelExecutionState
    from .model_unicorn.speculator_abc import UnicornSpeculator
    from .model_unicorn.model import UnicornModel
    from .instruction_spec import InstructionSpec
    from .traces import HTrace, Violation, CTrace
    from .tc_components.test_case_data import InputData

MASK_64BIT = pow(2, 64)   # 64位掩码常量
POW2_64 = pow(2, 64)      # 2的64次方常量

# ANSI 终端颜色代码定义
RED = '\033[33;31m'
GREEN = '\033[33;32m'
YELLOW = '\033[33;33m'
BLUE = '\033[33;34m'
PURPLE = '\033[33;35m'
CYAN = '\033[33;36m'
GRAY = '\033[33;37m'
COL_RESET = "\033[0m"

# 模型追踪输出的颜色配置
M_COL = PURPLE     # 内存访问标记颜色
PC_COL = COL_RESET  # PC（程序计数器）颜色
VAL_COL = CYAN      # 值颜色

# 硬件追踪对比输出的颜色配置
HTRACE_R1_COL = CYAN    # 硬件追踪行1颜色
HTRACE_R2_COL = YELLOW  # 硬件追踪行2颜色

STAT = FuzzingStats()  # 全局模糊测试统计对象


# ==================================================================================================
# 内部：日志配置管理
# ==================================================================================================
class _LoggingConfig:  # pylint: disable=too-few-public-methods  # because this is a data class
    """
    全局日志配置管理类 - 使用 Borg 模式确保所有实例共享同一状态。

    该类负责跟踪日志输出模式（info/stat/debug 等）和显示方式
    （单行重绘/多行输出），由 CONF.logging_modes 配置项驱动。

    所有日志类（FuzzLogger、ModelLogger 等）通过创建 _LoggingConfig 实例
    获取配置，由于 Borg 模式，它们实际上共享同一配置状态。
    """
    _borg_shared_state: Dict[Any, Any] = {}  # Borg 模式共享状态

    redraw_mode: bool = True       # 是否使用单行重绘模式（进度条等）
    line_ending: str = ""          # 行尾字符（重绘模式为空，多行模式为换行）

    # 信息模式开关
    info: bool = False             # 是否显示信息级别日志
    stat: bool = False             # 是否显示统计信息
    debug: bool = False            # 是否启用任何调试模式

    # 各模块的调试开关
    dbg_timestamp: bool = False      # 时间戳调试
    dbg_violation: bool = False      # 违规详细信息调试
    dbg_dump_htraces: bool = False   # 硬件追踪转储调试
    dbg_dump_ctraces: bool = False   # 合约追踪转储调试
    dbg_dump_traces_unlimited: bool = False  # 无限制追踪转储
    dbg_executor_raw: bool = False   # 执行器原始数据调试
    dbg_model: bool = False          # 模型执行追踪调试
    dbg_coverage: bool = False       # 覆盖率调试
    dbg_generator: bool = False      # 程序生成器调试
    dbg_priming: bool = False        # priming 阶段调试
    dbg_isa_filter: bool = False     # ISA 指令过滤调试

    dbg_model_print_id: bool = True  # 模型调试中是否打印输入 ID

    _all_modes: List[str] = [
        "info", "stat", "dbg_timestamp", "dbg_violation", "dbg_dump_htraces", "dbg_dump_ctraces",
        "dbg_dump_traces_unlimited", "dbg_executor_raw", "dbg_model", "dbg_coverage",
        "dbg_generator", "dbg_priming", "dbg_isa_filter"
    ]
    """所有合法的日志模式名称列表"""

    def __init__(self) -> None:
        """初始化日志配置 - 实现 Borg 模式使所有实例共享同一状态"""
        self.__dict__ = self._borg_shared_state
        if not self._borg_shared_state:
            self.update_logging_modes()
            self.line_ending = '\n' if CONF.multiline_output else ''
            self.redraw_mode = not CONF.multiline_output

    def update_logging_modes(self) -> None:
        """
        根据 CONF.logging_modes 更新日志配置模式。

        处理逻辑：
        1. 验证所有配置的日志模式名称是否合法
        2. 设置各模式开关（info/stat/各 dbg 模式）
        3. 若需要调试模式但 Python 运行在优化模式（-O），发出警告
        """
        # 验证配置中的日志模式名称是否合法
        for mode in CONF.logging_modes:
            if not mode:  # 跳过空值
                continue
            if mode not in self._all_modes:
                error(f"Unknown value '{mode}' of config variable 'logging_modes'")

        # 设置各日志模式开关
        self.debug = False
        for mode in self._all_modes:
            val = mode in CONF.logging_modes  # 检查该模式是否在配置中启用
            setattr(self, mode, val)
            if "dbg" in mode:
                self.debug |= val  # 任一 dbg 模式启用则 debug=True

        # 检查 Python 是否运行在优化模式（-O）下，
        # 若需要调试模式但 Python 优化模式会跳过 __debug__ 相关代码
        if not __debug__:
            dbg_required = any([
                self.dbg_timestamp, self.dbg_model, self.dbg_coverage, self.dbg_dump_htraces,
                self.dbg_dump_ctraces, self.dbg_generator, self.dbg_priming, self.dbg_executor_raw,
                self.dbg_isa_filter
            ])
            if dbg_required:
                warning(
                    "", "Current value of `logging_modes` requires debugging mode!\n"
                    "Remove '-O' from python arguments")


# ==================================================================================================
# 日志配置的公共接口
# ==================================================================================================
# 创建日志配置的初始实例供本模块的函数使用
_LOG_CONF = _LoggingConfig()


def update_logging_after_config_change() -> None:
    """ 在 CONF 配置变更后更新日志配置 """
    _LOG_CONF.update_logging_modes()


# ==================================================================================================
# 公共：基础日志函数
# ==================================================================================================
# FIXME: 已弃用；应使用异常代替
def error(msg: str, print_tb: bool = False, print_last_tb: bool = False) -> NoReturn:
    """打印错误消息并退出程序。

    参数:
        msg: 错误消息内容
        print_tb: 是否打印完整调用栈追踪
        print_last_tb: 是否打印最近3层调用栈追踪

    该函数打印红色错误消息后以退出码 1 终止程序。
    """
    if _LOG_CONF.redraw_mode:
        print("")  # 重绘模式下先换行以清除进度条

    if print_tb:
        print("Encountered an unrecoverable error\nTraceback:")
        print_stack()
        print("\n")
    elif print_last_tb:
        print("Encountered an unrecoverable error\nTraceback:")
        print_stack(limit=3)
        print("\n")

    if CONF.color:
        print(f"{RED}ERROR:{COL_RESET} {msg}")
    else:
        print(f"ERROR: {msg}")
    sys.exit(1)


def warning(src: str, msg: str) -> None:
    """打印警告消息。

    参数:
        src: 警告来源模块名称
        msg: 警告消息内容
    """
    if _LOG_CONF.redraw_mode:
        print("")
    if CONF.color:
        print(f"{RED}WARNING:{COL_RESET} [{src}] {msg}")
    else:
        print(f"WARNING: [{src}] {msg}")


def inform(src: str, msg: str, end: str = "\n") -> None:
    """打印信息级别消息（仅在 info 模式启用时输出）。

    参数:
        src: 信息来源模块名称
        msg: 信息消息内容
        end: 行尾字符，默认为换行
    """
    if _LOG_CONF.info:
        if _LOG_CONF.redraw_mode:
            print("")
        print(f"INFO: [{src}] {msg}", end=end, flush=True)


def dbg(src: str, msg: str) -> None:
    """打印调试消息（仅在 debug 模式启用且 __debug__ 为 True 时输出）。

    参数:
        src: 调试来源模块名称
        msg: 调试消息内容
    """
    if not __debug__:
        return
    if _LOG_CONF.debug:
        if _LOG_CONF.redraw_mode:
            print("")
        print(f"DBG: [{src}] {msg}")


# ==================================================================================================
# 公共：模糊测试器专用日志类
# ==================================================================================================
class FuzzLogger:
    """ 模糊测试器日志类 - 提供模糊测试循环的进度显示和阶段报告。

    主要功能：
    - 进度条更新（显示测试用例数量、百分比、简要统计）
    - priming 阶段提示
    - 推测嵌套层级增加提示
    - 慢路径进入提示
    - 超时提示
    - 样本大小增加提示
    - 违规检测报告
    - 完成时的时间与统计报告
    """

    one_percent_progress: float = 0.0   # 每百分之一的进度增量
    progress: float = 0.0               # 当前累计进度
    progress_percent: int = 0           # 当前进度百分比整数
    msg: str = ""                       # 当前进度条消息
    _msg_width: int = 0                 # 进度条消息最大宽度（用于单行重绘）
    start_time: datetime                # 模糊测试开始时间
    _conf: Final[_LoggingConfig]        # 日志配置引用

    def __init__(self) -> None:
        self._conf = _LoggingConfig()

    # ----------------------------------------------------------------------------------------------
    # 模糊测试各阶段的日志方法

    def reset(self, max_iterations: int, start_time: datetime) -> None:
        """重置模糊测试器的日志状态。

        参数:
            max_iterations: 最大迭代次数（用于计算进度百分比）
            start_time: 模糊测试开始时间
        """
        self.one_percent_progress = max_iterations / 100
        self.progress = 0
        self.progress_percent = 0
        self.msg = ""
        self.start_time = start_time

    def start(self, iterations: int, start_time: datetime) -> None:
        """打印模糊测试开始消息（显示开始时间）。

        参数:
            iterations: 总迭代次数
            start_time: 开始时间
        """
        self.reset(iterations, start_time)
        if not self._conf.info:
            return
        inform("fuzzer", start_time.strftime('Starting at %H:%M:%S'))

    def start_round(self, round_id: int) -> None:
        """更新模糊测试进度条。

        在 info 模式启用时，每轮测试用例更新进度百分比和统计摘要。
        在 dbg_timestamp 模式启用时，每 1000 轮打印时间戳。

        参数:
            round_id: 当前轮次编号
        """
        if not self._conf.info:
            return

        # 更新进度状态
        if STAT.test_cases > self.progress:
            self.progress += self.one_percent_progress
            self.progress_percent += 1
        if STAT.test_cases == 0:
            msg = ""
        else:
            msg = f"\r{STAT.test_cases:<6}({self.progress_percent:>2}%)| Stats: "
            msg += STAT.get_brief()
        self.msg = msg

        # 打印进度条
        if STAT.test_cases > 0:
            print(f"{self.msg:<{self._msg_width}}", end=self._conf.line_ending, flush=True)
        if self._conf.dbg_timestamp and round_id and round_id % 1000 == 0:
            dbg(
                "fuzzer", f"Time: {datetime.today()} | "
                f" Duration: {(datetime.today() - self.start_time).total_seconds()} seconds")

    def priming(self, num_violations: int) -> None:
        """打印 priming 阶段提示消息。

        参数:
            num_violations: 当前检测到的违规数量
        """
        if not self._conf.info:
            return
        msg = self.msg + f"> Priming  {num_violations}             "
        print(msg, end=self._conf.line_ending, flush=True)
        self._msg_width = max(self._msg_width, len(msg))

    def nesting_increased(self) -> None:
        """打印推测嵌套层级增加提示消息。"""
        if not self._conf.info:
            return
        msg = self.msg + f"> Nest   {CONF.model_max_nesting}         "
        self._msg_width = max(self._msg_width, len(msg))
        print(msg, end=self._conf.line_ending, flush=True)

    def slow_path(self) -> None:
        """打印进入慢路径的提示消息。"""
        if not self._conf.info:
            return
        msg = self.msg + ">" + " Entering slow path..."
        self._msg_width = max(self._msg_width, len(msg))
        print(msg, end=self._conf.line_ending, flush=True)

    def timeout(self) -> None:
        """打印超时提示消息。"""
        if not self._conf.info:
            return
        inform("fuzzer", "\nTimeout expired")

    def sample_size_increase(self, sample_size: int) -> None:
        """打印样本大小增加提示消息。

        参数:
            sample_size: 新的样本大小
        """
        if not self._conf.info:
            return
        msg = self.msg + ">" + " Increasing sample size... to " + str(sample_size)
        self._msg_width = max(self._msg_width, len(msg))
        print(msg, end=self._conf.line_ending, flush=True)

    def report_violations(self, violation: Violation) -> None:
        """打印检测到的违规的完整报告。

        参数:
            violation: 检测到的违规对象
        """
        print("\n\n================================ Violations detected ==========================")
        print(violation.full_str())

    def finish(self) -> None:
        """打印模糊测试完成消息（显示持续时间和结束时间，以及统计信息）。"""
        if not self._conf.info:
            return
        now = datetime.today()
        print("")  # 进度条后换行
        if self._conf.stat:
            print("================================ Statistics ================================"
                  "===\n")
            print(STAT)
        print(f"Duration: {(now - self.start_time).total_seconds():.1f}")
        print(datetime.today().strftime('Finished at %H:%M:%S'))

    def report_model_coverage(self, model: Model) -> None:
        """保存模型覆盖率报告到文件。

        参数:
            model: 合约模型实例
        """
        if not __debug__:
            return
        if not self._conf.dbg_coverage:
            return
        model.report_coverage("coverage.txt")

    # ----------------------------------------------------------------------------------------------
    # 调试方法
    def dbg_dump_traces(self, inputs: List[InputData], htraces: List[HTrace],
                        reference_htraces: List[HTrace], ctraces: List[CTrace]) -> None:
        """转储收集的追踪数据（硬件追踪和合约追踪）。

        在 dbg_dump_htraces 或 dbg_dump_ctraces 模式启用时输出追踪详情。
        可选限制输出到前 100 个输入（除非启用 dbg_dump_traces_unlimited）。
        被损坏的硬件追踪会用参考追踪替换。

        参数:
            inputs: 输入数据列表
            htraces: 硬件追踪列表
            reference_htraces: 参考硬件追踪列表（用于替换损坏追踪）
            ctraces: 合约追踪列表
        """
        if not __debug__:
            return
        if not self._conf.dbg_dump_htraces and not self._conf.dbg_dump_ctraces:
            return
        if not htraces:  # 可能因追踪错误而为空
            return

        # 可选限制输出数量
        if len(inputs) > 100 and not self._conf.dbg_dump_traces_unlimited:
            warning("fuzzer", "Trace output is will be limited to 100 traces")
            inputs = inputs[:100]

        # 用参考追踪替换损坏的硬件追踪
        for i, htrace in enumerate(htraces):
            if htrace.is_corrupted_or_ignored() \
               and not reference_htraces[i].is_corrupted_or_ignored():
                htraces[i] = reference_htraces[i]

        print("\n================================ Collected Traces =============================")
        org_debug_state = self._conf.dbg_model
        self._conf.dbg_model = False  # 临时禁用模型调试以避免干扰追踪输出
        for i, _ in enumerate(inputs):
            print(f"- Input {i}:")
            colors: Tuple[str, ...]
            if self._conf.dbg_dump_ctraces:
                colors = (M_COL, PC_COL, VAL_COL, COL_RESET) if CONF.color else ()
                ctrace_str = ctraces[i].full_str(*colors)
                print(f"  CTr: {ctrace_str} | Hash: {ctraces[i]}")
            if self._conf.dbg_dump_htraces:
                colors = (HTRACE_R1_COL, HTRACE_R2_COL, COL_RESET) if CONF.color else ()
                htrace_str = htraces[i].full_str('    ', *colors)
                print(f"  HTr:\n{htrace_str}")
            if CONF.color and htraces[i].get_max_pfc()[0] > htraces[i].get_max_pfc()[1]:
                print(f"  Feedback: {YELLOW}{htraces[i].get_max_pfc()}{COL_RESET}")
            else:
                print(f"  Feedback: {htraces[i].get_max_pfc()}")
        self._conf.dbg_model = org_debug_state  # 恢复模型调试状态

    def dbg_dump_architectural_traces(self, hardware_regs: List[List[int]],
                                      model_regs: List[List[int]]) -> None:
        """转储架构级追踪（硬件寄存器值与模型寄存器值的对比）。

        仅在 architectural 模式模糊测试且追踪转储调试模式启用时输出。

        参数:
            hardware_regs: 硬件寄存器值列表
            model_regs: 模型寄存器值列表
        """
        if not __debug__:
            return
        if CONF.fuzzer != "architectural":
            return
        if not self._conf.dbg_dump_htraces and not self._conf.dbg_dump_ctraces:
            return

        print("\n========================== Architectural Traces ==============================")
        for i, _ in enumerate(hardware_regs):
            if i > 100 and not self._conf.dbg_dump_traces_unlimited:
                warning("fuzzer", "Trace output is limited to 100 traces")
                break
            print(f"Input {i}:")
            if self._conf.dbg_dump_ctraces:
                print(f"  Model Registers: {[hex(v) for v in model_regs[i]]}")
            if self._conf.dbg_dump_htraces:
                print(f"  HW Registers:    {[hex(v) for v in hardware_regs[i]]}")

    def dbg_violation(self, violation: Violation, model: Model) -> None:
        """打印违规的详细追踪报告。

        对每个硬件追踪类别，重新在模型中追踪测试用例，
        输出每个输入的模型执行过程详情。

        参数:
            violation: 检测到的违规对象
            model: 合约模型实例
        """
        if not __debug__:
            return

        if self._conf.dbg_violation:
            print("================================ Violation Traces =============================")
            hw_classes = violation.get_hw_classes()
            model.load_test_case(violation.test_case_code)
            for hw_class in hw_classes:
                measurement = hw_class.measurements[0]
                print(f"                      ##### Input {measurement.input_id} #####")
                model_debug_state = self._conf.dbg_model, self._conf.dbg_model_print_id
                self._conf.dbg_model = True       # 临时启用模型调试
                self._conf.dbg_model_print_id = False
                model.trace_test_case([measurement.input_], CONF.model_max_nesting)
                self._conf.dbg_model, self._conf.dbg_model_print_id = model_debug_state
                print("\n\n")

    def dbg_priming_progress(self, input_id: int, current_input_id: int) -> None:
        """打印 priming 阶段的进度提示。

        参数:
            input_id: 用于 priming 的输入编号
            current_input_id: 被替换的原始输入编号
        """
        if not __debug__:
            return
        if not self._conf.dbg_priming:
            return
        print(f"\nPriming #{input_id} in place of #{current_input_id}")

    def dbg_priming_fail(self, input_id: int, current_input_id: int, htrace_to_reproduce: HTrace,
                         new_htrace: HTrace) -> None:
        """打印 priming 失败的消息，对比原始追踪和新追踪。

        参数:
            input_id: 用于 priming 的输入编号
            current_input_id: 被替换的原始输入编号
            htrace_to_reproduce: 需要重现的原始硬件追踪
            new_htrace: priming 后的新硬件追踪
        """
        if not __debug__:
            return
        if not self._conf.dbg_priming:
            return

        print(f"\nPriming failed for input {input_id} in place of {current_input_id}")
        print(f"{'HTrace':64} Original|New")
        print(htrace_to_reproduce.full_pair_str(new_htrace))


class ModelLogger:
    """
    合约模型日志类 - 提供模型执行过程的调试追踪输出。

    主要功能：
    - 调试追踪头部（显示当前输入编号）
    - 内存访问调试（显示加载/存储的地址和值）
    - 指令执行调试（显示指令名称、寄存器值、推测状态）
    - 推测回滚消息
    - 异常消息
    """

    model_layout: Optional[SandboxLayout] = None  # 模型沙箱布局（用于地址规范化）

    def __init__(self) -> None:
        self._conf = _LoggingConfig()

    def set_model_layout(self, layout: SandboxLayout) -> None:
        """存储模型的沙箱布局（用于将地址转换为偏移量）。

        参数:
            layout: 模型的沙箱布局对象
        """
        self.model_layout = layout

    def dbg_header(self, input_id: int) -> None:
        """打印调试追踪的头部信息（显示当前输入编号）。

        参数:
            input_id: 当前输入编号
        """
        if not __debug__:
            return
        if not self._conf.dbg_model or not self._conf.dbg_model_print_id:
            return

        print(f"\n                     ##### Input {input_id} #####")

    def dbg_mem_access(self, is_store: bool, value: int, address: int, size: int,
                       model: UnicornModel, layout: SandboxLayout) -> None:
        """
        打印内存访问的调试信息。

        显示内存地址（转换为数据区偏移量）、访问类型（加载/存储）、
        读写值等信息。对存储操作直接显示传入的值，
        对加载操作从模拟器内存中读取实际值。

        :param is_store: 是否为存储操作（True 为 store，False 为 load）
        :param value: 存储操作的写入值
        :param address: 被访问的内存地址
        :param size: 内存访问的字节大小
        :param model: 被调试的合约模型实例
        :param layout: 模型的沙箱布局
        :return: None
        """
        if not __debug__:
            return
        if not self._conf.dbg_model:
            return

        # 地址转换 - 将绝对地址转换为数据区偏移量便于理解
        normalized_address = layout.data_addr_to_offset(address)

        # 值处理 - 存储操作直接使用传入值，加载操作从模拟器内存读取
        val = value if is_store else int.from_bytes(
            model.emulator.mem_read(address, size), byteorder='little')

        # 构建并打印报告字符串
        type_str = "store to" if is_store else "load from"
        if CONF.color:
            msg = f"    > {CYAN}{type_str}{COL_RESET} +0x{normalized_address:x} " \
                  f"{CYAN}value {COL_RESET}0x{val:x}"
        else:
            msg = f"    > {type_str} +0x{normalized_address:x} value 0x{val:x}"

        print(msg)

    def dbg_instruction(self, pc: int, model: UnicornModel, state: ModelExecutionState,
                        speculator: UnicornSpeculator) -> None:
        """
        打印当前指令的调试信息。

        显示内容包括：
        - 指令名称和操作数
        - 当前寄存器值
        - 是否处于推测执行状态（推测中则显示嵌套层级）
        - 是否为测试用例退出指令

        推测中的指令用黄色标记，正常指令用绿色标记。

        :param pc: 当前程序计数器值
        :param model: 被调试的合约模型实例
        :param state: 模型执行状态对象
        :param speculator: 推测器实例
        """
        if not __debug__:
            return
        if not self._conf.dbg_model:
            return

        # 指令详情
        instruction = state.current_instruction
        name = str(instruction)
        code_offset = model.layout.code_addr_to_offset(pc)
        is_exit = state.is_exit_addr(pc)

        # 推测状态详情
        in_speculation = speculator.in_speculation()
        nesting = speculator.nesting()

        # 构建并打印指令字符串 - 推测中用黄色，正常用绿色
        inst_str = name
        if CONF.color:
            if in_speculation:
                inst_str = YELLOW + inst_str + COL_RESET
            else:
                inst_str = GREEN + inst_str + COL_RESET
        if in_speculation:
            inst_str = f"[transient, nesting = {nesting}] " + inst_str  # 推测中标记嵌套层级
        inst_str = f"0x{code_offset:<2x}: {inst_str}"
        if is_exit:
            inst_str += " [test_case_exit]"
        print(inst_str)

        # 打印当前寄存器值
        model.print_registers(oneline=True)

    def dbg_rollback(self, address: int) -> None:
        """打印推测回滚消息 - 显示模型回滚到的地址。

        参数:
            address: 回滚目标地址
        """
        if not __debug__:
            return
        if not self._conf.dbg_model:
            return

        assert self.model_layout is not None
        base = self.model_layout.code_start()

        msg = f"ROLLBACK to 0x{address - base:x}"
        if CONF.color:
            msg = YELLOW + msg + COL_RESET
        print(msg)

    def dbg_exception(self, errno: int, descr: str) -> None:
        """打印异常消息 - 显示异常编号和描述。

        参数:
            errno: 异常编号
            descr: 异常描述文本
        """
        if not __debug__:
            return

        if not self._conf.dbg_model:
            return

        msg = f"EXCEPTION #{errno}: {descr}"
        if CONF.color:
            msg = RED + msg + COL_RESET
        print(msg)


class GeneratorLogger:
    """ 程序生成器日志类 - 提供生成器调试输出服务。"""

    def __init__(self) -> None:
        self._conf = _LoggingConfig()

    def dbg_dump_instruction_pool(self, instructions: List[InstructionSpec]) -> None:
        """
        打印程序生成器使用的指令池。

        在 dbg_generator 模式启用时，按类别分组打印可用指令列表，
        显示每个类别中的指令名称和总数。

        参数:
            instructions: 指令规范对象列表
        """
        if not __debug__:
            return
        if not self._conf.dbg_generator or not CONF.is_generation_enabled():
            return

        # 按类别分组指令
        instructions_by_category: Dict[str, Set[str]] = {i.category: set() for i in instructions}
        for i in instructions:
            instructions_by_category[i.category].add(i.name)
        n_instructions = sum(len(v) for v in instructions_by_category.values())

        dbg("generator", f"Instructions under test {n_instructions}:")
        for k, instruction_list in instructions_by_category.items():
            print("  - " + k + ": " + pformat(sorted(instruction_list), indent=4, compact=True))
        print("")


class ExecutorLogger:
    """ 执行器日志类 - 提供执行器调试输出服务。"""

    def __init__(self) -> None:
        self._conf = _LoggingConfig()

    def dbg_dump_raw_traces(self, htraces: List[HTrace]) -> None:
        """打印执行器收集的原始硬件追踪数据。

        在 dbg_executor_raw 模式启用时输出。

        参数:
            htraces: 硬件追踪列表
        """
        if not __debug__:
            return
        if not self._conf.dbg_executor_raw:
            return

        print("Collected raw traces:")
        for input_id, htrace in enumerate(htraces):
            prefix = f"{input_id:03}, "
            print(htrace.full_str(prefix))


class ISALogger:
    """ ISA 规范日志类 - 提供指令过滤的调试输出服务。"""

    def __init__(self) -> None:
        self._conf = _LoggingConfig()

    def dbg_dump_filtering_reason(self, instruction: InstructionSpec, reason: str) -> None:
        """
        打印指令被 ISA 规范模块过滤掉的原因。

        在 dbg_isa_filter 模式启用时，显示被过滤指令的名称、类别和过滤原因。

        参数:
            instruction: 被过滤的指令规范对象
            reason: 过滤原因描述
        """
        if not __debug__:
            return
        if not self._conf.dbg_isa_filter or not CONF.is_generation_enabled():
            return

        dbg("isa_spec", f"{instruction.name} ({instruction.category}) filtered out: {reason}")
