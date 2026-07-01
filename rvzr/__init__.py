"""
rvzr 包初始化文件 - 微架构侧信道模糊测试框架的顶层包入口。

本文件负责导出框架的所有核心模块，使外部可以通过 `import rvzr` 
直接访问 ISA 规范解析、执行器、分析器、数据/代码生成器、CLI、
日志、模型、模糊测试器、工厂、配置、汇编解析器、架构支持等子模块。
"""
# flake8: noqa
# pylint: skip-file

from .isa_spec import *        # ISA 规范解析模块 - 加载指令集定义文件
from .executor import *        # 执行器模块 - 在真实硬件上运行测试用例并收集硬件追踪
from .analyser import *        # 分析器模块 - 比较合约追踪与硬件追踪，检测违规
from .data_generator import *  # 输入数据生成器模块 - 为测试用例生成随机输入
from .code_generator import *  # 代码生成器模块 - 生成随机测试用例程序
from .cli import *             # 命令行接口模块 - 提供命令行参数解析与执行入口
from .logs import *            # 日志模块 - 提供全局日志与调试输出基础设施

from .model import *           # 合约模型模块 - 基于合约规范模拟程序执行行为
from .fuzzer import *          # 模糊测试器模块 - 核心模糊测试循环与策略
from .factory import *         # 工厂模块 - 根据配置创建各组件实例
from .config import *          # 配置模块 - 全局配置选项的加载与管理

from .asm_parser import *      # 汇编解析器模块 - 解析汇编代码为内部表示

from .arch.x86 import *        # x86-64 架构支持模块
from .model_unicorn import *   # Unicorn 模拟器后端模块 - 使用 Unicorn 引擎执行合约追踪
from .postprocessing import *  # 后处理模块 - 包含测试用例最小化等功能

__version__ = "2.0.0"  # 框架版本号
