"""
文件：DynamoRIO后端生成的二进制追踪解码器。

该模块提供了解码DynamoRIO后端输出的二进制追踪文件的完整功能，包括：
- 普通追踪（leakage trace）的解码：包含PC、内存读写、间接调用等条目
- 调试追踪（debug trace）的解码：包含寄存器转 dump、内存访问、异常等条目
- 追踪文件完整性检查

使用CFFI库解析C语言结构体定义，将二进制数据解码为Python可操作的对象。

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

from enum import Enum
from typing import Any, Final, List, Literal, Union, cast
from io import BufferedReader
import sys
import os

from cffi import FFI
from typing_extensions import get_args, assert_never

_MarkerType = Literal["T", "D"]  # 追踪文件类型标记：T=普通追踪，D=调试追踪

# ==================================================================================================
# 追踪类型定义
# ==================================================================================================
# TODO: 从trace.hpp自动生成
# 注意：cffi无法解析CPP构造（如enum class、std::array），因此需要手动调整部分字段。


class TraceEntryType(Enum):
    """
    追踪条目类型枚举，从trace.hpp复制而来。
    TODO: cffi无法解析enum class，需找到从头文件自动生成的方法
    """
    ENTRY_EOT = 0  # 追踪结束标记
    ENTRY_PC = 1   # 程序计数器（指令地址）
    ENTRY_READ = 2  # 内存读取
    ENTRY_WRITE = 3  # 内存写入
    ENTRY_EXCEPTION = 4  # 异常
    ENTRY_IND = 5   # 间接调用目标地址


# 普通追踪条目的C结构体定义（用于CFFI解析）
_TRACE_ENTRY_T: Final[str] = "struct trace_entry_t"
_TRACE_ENTRY_DEF: Final[str] = """
struct trace_entry_t {
    // pc for instructions; address for memory accesses; target for indirect calls
    // 指令的PC值；内存访问的地址；间接调用的目标地址
    uint64_t addr;
    // instruction size for instructions; memory access size for memory accesses
    // 指令大小；内存访问大小
    uint32_t size;
    // see trace_entry_type_t
    // 条目类型，参见TraceEntryType
    uint8_t type;
    // unused for now
    // 当前未使用
    uint8_t padding[3]; // NOLINT
};
"""

# ==================================================================================================
# 调试追踪类型定义
# ==================================================================================================
# TODO: 从debug_trace.hpp自动生成
# 注意：cffi无法解析CPP构造，需手动调整。


class DebugTraceEntryType(Enum):
    """
    调试追踪条目类型枚举，从debug_trace.hpp复制而来。
    TODO: cffi无法解析enum class，需找到从头文件自动生成的方法
    """
    ENTRY_EOT = 0  # 追踪结束标记
    ENTRY_REG_DUMP = 1  # 寄存器转 dump
    ENTRY_READ = 2  # 内存读取
    ENTRY_WRITE = 3  # 内存写入
    ENTRY_LOC = 4   # 位置信息（模块名和偏移）
    ENTRY_EXCEPTION = 5  # 异常
    ENTRY_CHECKPOINT = 6  # 检查点（推测执行回滚用）
    ENTRY_ROLLBACK = 7  # 回滚（推测执行回滚）
    ENTRY_ROLLBACK_STORE = 8  # 回滚存储（恢复内存值）
    ENTRY_REG_DUMP_EXTENDED = 9  # 扩展寄存器转 dump


# 调试追踪条目的C结构体定义（用于CFFI解析）
_DEBUG_TRACE_ENTRY_T: Final[str] = "struct debug_trace_entry_t"
_DEBUG_TRACE_ENTRY_DEF: Final[str] = """
struct debug_trace_entry_t {
    // What does this entry contain
    // 条目内容类型
    uint8_t type;
    // Nested speculation (0 is architectural)
    // 嵌套推测级别（0表示架构级，即非推测）
    uint8_t nesting_level;
    // Unused for now
    // 当前未使用
    uint8_t padding[6]; // NOLINT

    // Union of all possible entry types
    // 所有可能条目类型的联合体
    union {
        // ENTRY_REG_DUMP - 寄存器转 dump
        struct {
            uint64_t xax;
            uint64_t xbx;
            uint64_t xcx;
            uint64_t xdx;
            uint64_t xsi;
            uint64_t xdi;
            uint64_t pc;
        } regs;
        // ENTRY_REG_EXTENDED - 扩展寄存器
        struct {
            uint64_t rsp;
            uint64_t rbp;
            uint64_t flags;
            uint64_t r8;
            uint64_t r9;
            uint64_t r10;
            uint64_t r11;
        } regs_2;
        // ENTRY_MEM (read or write) - 内存读写
        struct {
            uint64_t address;
            uint64_t value;
            uint64_t size;
        } mem;
        // ENTRY_LOC (module name and offset, for disassembly) - 位置信息
        struct {
            uint64_t offset;
            char module_name[48]; // NOLINT
        } loc;
        // ENTRY_EXCEPTION - 异常
        struct {
            int signal;
            uint64_t address;
        } xcpt;
        // ENTRY_CHECKPOINT - 检查点
        struct {
            uint64_t rollback_pc;
            uint64_t cur_window_size;
            size_t cur_store_log_size;
        } checkpoint;
        // ENTRY_ROLLBACK - 回滚
        struct {
            unsigned nesting;
            uint64_t rollback_pc;
        } rollback;
        // ENTRY_ROLLBACK_STORE - 回滚存储
        struct {
            uint64_t addr;
            uint64_t val;
            size_t size;
            uint64_t nesting_level;
        } rollback_store;
    };
};
"""


# ==================================================================================================
# 解码器类
# ==================================================================================================
class TraceDecoder:
    """
    追踪解码器类，提供统一的API用于解码追踪条目。
    使用CFFI库将二进制数据解析为C结构体对象。
    支持普通追踪和调试追踪的解码，以及追踪文件完整性检查。
    """

    _ffi: FFI  # CFFI实例，用于解析C结构体定义
    _trace_entry_size: int  # 普通追踪条目的大小（字节）
    _debug_trace_entry_size: int  # 调试追踪条目的大小（字节）

    def __init__(self) -> None:
        self._ffi = FFI()
        # 解析普通追踪结构体定义
        self._ffi.cdef(_TRACE_ENTRY_DEF)
        self._trace_entry_size = self._ffi.sizeof(_TRACE_ENTRY_T)
        # 解析调试追踪结构体定义
        self._ffi.cdef(_DEBUG_TRACE_ENTRY_DEF)
        self._debug_trace_entry_size = self._ffi.sizeof(_DEBUG_TRACE_ENTRY_T)

    # ----------------------------------------------------------------------------------------------
    # 公共API
    # ----------------------------------------------------------------------------------------------
    def read_trace_marker(self, f: BufferedReader) -> Union[_MarkerType, Literal[""]]:
        """
        读取追踪文件的类型标记。
        文件开头8字节中，第1字节为类型标记（T或D），其余7字节为填充。
        :return: "T"（普通追踪）、"D"（调试追踪）或空字符串（空文件）
        """
        marker = f.read(1).decode('utf-8')
        if len(marker) == 0:
            return ""  # 空文件
        assert marker in get_args(_MarkerType), f"Unknown trace type marker: {marker}"
        f.read(7)  # 跳过7字节填充
        return cast(_MarkerType, marker)

    def decode_trace_file(self, file: str) -> List[List[Any]]:
        """
        从文件中读取一组普通追踪。
        每条追踪由一系列条目组成，以ENTRY_EOT条目结束。
        :param file: 追踪文件路径
        :return: 追踪列表，每条追踪为条目列表
        """
        with open(file, "rb") as f:
            marker = self.read_trace_marker(f)
            if marker == "":  # 空文件
                return []
            assert marker == "T", f"Expected Normal trace (T), got {marker}"

            # 读取追踪
            traces = []
            eof = False
            while not eof:

                entries = []
                while True:
                    # 读取一个条目
                    chunk = f.read(self._trace_entry_size)
                    if len(chunk) < self._trace_entry_size:
                        eof = True
                        break  # 没有更多字节可读：退出

                    # 解码条目
                    entry = self._decode_trace_entry(chunk)
                    entries.append(entry)

                    # 如果到达EOT，继续读取下一条追踪
                    if TraceEntryType(entry.type) == TraceEntryType.ENTRY_EOT:
                        traces.append(entries)
                        break

                # 检查最后一条追踪是否以EOT或EXCEPTION条目结束
                if eof and len(entries) > 0:
                    last_entry = entries[-1]
                    if TraceEntryType(last_entry.type) != TraceEntryType.ENTRY_EOT:
                        raise ValueError("Trace file does not end with an EOT entry")

        return traces

    def decode_debug_trace_file(self, file: str) -> List[List[Any]]:
        """
        从文件中读取一组调试追踪。
        每条调试追踪由一系列调试条目组成，以ENTRY_EOT条目结束。
        :param file: 调试追踪文件路径
        :return: 调试追踪列表，每条追踪为条目列表
        """
        with open(file, "rb") as f:
            marker = self.read_trace_marker(f)
            if marker == "":  # 空文件
                return []
            assert marker == "D", f"Expected Debug trace (D), got {marker}"

            # 读取追踪
            traces = []
            eof = False
            while not eof:

                entries = []
                while True:
                    # 读取一个条目
                    chunk = f.read(self._debug_trace_entry_size)
                    if len(chunk) < self._debug_trace_entry_size:
                        eof = True
                        break  # 没有更多字节可读：退出

                    # 解码条目
                    entry = self._decode_debug_trace_entry(chunk)
                    entries.append(entry)

                    # 如果到达EOT，继续读取下一条追踪
                    if DebugTraceEntryType(entry.type) == DebugTraceEntryType.ENTRY_EOT:
                        traces.append(entries)
                        break

                # 检查最后一条追踪是否以EOT或EXCEPTION条目结束
                if eof and len(entries) > 0:
                    last_entry = entries[-1]
                    if DebugTraceEntryType(last_entry.type) != DebugTraceEntryType.ENTRY_EOT:
                        raise ValueError("Trace file does not end with an EOT entry")

        return traces

    def is_trace_corrupted(self, trace_path: str) -> bool:
        """
        检查追踪文件是否损坏（即不以EOT或EXCEPTION条目结束）。
        :param trace_path: 追踪文件路径
        :return: True表示追踪损坏，False表示追踪正常
        """
        # 空文件或不存在文件视为损坏
        if not os.path.exists(trace_path) or os.stat(trace_path).st_size == 0:
            return True

        with open(trace_path, "rb") as f:
            trace_type = self.read_trace_marker(f)
            if trace_type == "":
                return True

            # 根据类型解码
            if trace_type == "T":
                entry_sz = self._ffi.sizeof(_TRACE_ENTRY_T)
                if os.stat(trace_path).st_size < entry_sz:
                    return True

                # 解码最后一个条目
                f.seek(-entry_sz, os.SEEK_END)
                last_entry = self._decode_trace_entry(f.read(entry_sz))

                # 检查条目类型
                last_entry_type = TraceEntryType(last_entry.type)
                return last_entry_type != TraceEntryType.ENTRY_EOT

            if trace_type == "D":
                entry_sz = self._ffi.sizeof(_DEBUG_TRACE_ENTRY_T)
                if os.stat(trace_path).st_size < entry_sz:
                    return True

                # 解码最后一个条目
                f.seek(-entry_sz, os.SEEK_END)
                last_dbg_entry = self._decode_debug_trace_entry(f.read(entry_sz))

                # 检查条目类型
                last_dbg_entry_type = DebugTraceEntryType(last_dbg_entry.type)
                return last_dbg_entry_type != DebugTraceEntryType.ENTRY_EOT

            assert_never(trace_type)

    # ----------------------------------------------------------------------------------------------
    # 私有API
    # ----------------------------------------------------------------------------------------------
    def _decode_trace_entry(self, chunk: bytes) -> Any:
        """
        从字节块解码单个普通追踪条目。
        使用CFFI将二进制数据映射到trace_entry_t结构体。
        :param chunk: 包含一个追踪条目的字节块
        :return: 解码后的CFFI结构体对象
        """
        # 使用CFFI解码
        entry: Any = self._ffi.new(_TRACE_ENTRY_T + "*")
        self._ffi.memmove(entry, chunk, self._trace_entry_size)

        # 检查条目类型是否有效
        try:
            TraceEntryType(entry.type)
        except Exception:
            raise ValueError(f"Error: Unknown trace entry type {str(entry.type)}")

        return entry

    def _decode_debug_trace_entry(self, chunk: bytes) -> Any:
        """
        从字节块解码单个调试追踪条目。
        使用CFFI将二进制数据映射到debug_trace_entry_t结构体。
        :param chunk: 包含一个调试追踪条目的字节块
        :return: 解码后的CFFI结构体对象
        """
        # 使用CFFI解码
        entry: Any = self._ffi.new(_DEBUG_TRACE_ENTRY_T + "*")
        self._ffi.memmove(entry, chunk, self._debug_trace_entry_size)

        # 检查条目类型是否有效
        try:
            DebugTraceEntryType(entry.type)
        except Exception:
            raise ValueError(f"Error: Unknown debug entry type {str(entry.type)}")

        return entry


def main() -> None:
    """ 独立解码接口：从文件中漂亮打印追踪条目 """
    if len(sys.argv) != 2:
        print(f"Usage {sys.argv[0]} <TRACE_PATH>")
        sys.exit(1)

    # 1. 创建解码器
    decoder = TraceDecoder()

    # 2. 解码文件
    with open(sys.argv[1], "rb") as f:
        trace_type = decoder.read_trace_marker(f)
    if trace_type == "":
        print(f"Empty trace file: {sys.argv[1]}")
        sys.exit(1)
    if trace_type == "T":
        parsed_traces = decoder.decode_trace_file(sys.argv[1])
    elif trace_type == "D":
        parsed_traces = decoder.decode_trace_file(sys.argv[1])
        print(f"Only leakage traces allowed: found {len(parsed_traces)} debug traces instead")
        sys.exit(1)
    else:
        assert_never(trace_type)

    # 检查输入是否包含泄露追踪
    if len(parsed_traces) == 0:
        print(f"No traces found in {sys.argv[1]}")
        sys.exit(1)

    # 3. 打印所有条目
    for nt, trace_ in enumerate(parsed_traces):
        print("-------- TRACE --------")
        for ne, e in enumerate(trace_):
            try:
                # 解析条目类型
                type_ = TraceEntryType(e.type)
                print(f"[{type_.name}] {hex(e.addr)}")
            except Exception:
                raise ValueError(f"Failed to decode entry {ne} of trace {nt}")


if __name__ == '__main__':
    main()