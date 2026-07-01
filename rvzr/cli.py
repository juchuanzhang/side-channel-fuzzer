"""
文件：命令行工具的功能定义（Revizor 的 CLI 入口）
（注意：实际的 CLI 通过 revizor.py 访问）

本模块定义了侧信道模糊测试框架的命令行接口，包括参数解析和
各子命令（fuzz、tfuzz、reproduce、minimize、generate、analyse、download_spec）
的启动逻辑。main() 函数是核心入口，根据子命令类型调用相应的模糊测试器或工具。

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

import os
import sys
from typing import TYPE_CHECKING, Any
from argparse import ArgumentParser, ArgumentTypeError, ArgumentDefaultsHelpFormatter

import unicorn

from .factory import get_minimizer, get_fuzzer, get_downloader
from .config import CONF
from .logs import update_logging_after_config_change

if TYPE_CHECKING:
    from .fuzzer import FuzzingMode


def _arg2bool(arg: Any) -> bool:
    """将命令行参数转换为布尔值，支持多种字符串表示形式。

    参数:
        arg: 命令行参数值，可以是布尔值或字符串

    返回:
        对应的布尔值

    异常:
        ArgumentTypeError: 当参数无法转换为布尔值时抛出
    """
    if isinstance(arg, bool):
        return arg
    if arg.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    if arg.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    raise ArgumentTypeError('Boolean value expected.')


def _parse_args() -> Any:  # pylint: disable=r0915
    """解析命令行参数，构建各子命令的参数解析器。

    本函数定义了所有子命令及其参数选项，包括：
    - fuzz: 标准模糊测试模式
    - tfuzz: 基于模板的模糊测试模式
    - analyse: 独立的追踪分析接口
    - reproduce: 重现已检测到的违规
    - minimize: 测试用例最小化
    - generate: 独立的测试用例生成
    - download_spec: 下载 ISA 规范文件

    返回:
        解析后的命令行参数对象
    """
    parser = ArgumentParser(add_help=False)
    subparsers = parser.add_subparsers(dest='subparser_name')
    subparsers.required = True  # 必须指定子命令

    # ==============================================================================================
    # 公共参数 - 所有子命令共享的基础参数
    common_parser = ArgumentParser(add_help=False)
    common_parser.add_argument(
        "-c",
        "--config",
        type=str,
        required=False,
        help="Path to the configuration file (YAML) that will be used during fuzzing.",
    )
    common_parser.add_argument(
        "-I",
        "--include-dir",
        type=str,
        default=".",
        required=False,
        help="Path to the directory containing configuration files that included by the main "
        " configuration file (received via --config).",
    )
    common_parser.add_argument(
        "-s",
        "--instruction-set",
        type=str,
        required=True,
        help="Path to the instruction set specification (JSON) file.",
    )

    # ==============================================================================================
    # 模糊测试子命令 - 标准模糊测试模式的参数定义
    parser_fuzz = subparsers.add_parser(
        'fuzz',
        add_help=True,
        parents=[common_parser],
        formatter_class=ArgumentDefaultsHelpFormatter)
    parser_fuzz.add_argument(
        "-n",
        "--num-test-cases",
        type=int,
        default=1,
        help="Number of test cases.",
    )
    parser_fuzz.add_argument(
        "-i",
        "--num-inputs",
        type=int,
        default=100,
        help="Number of inputs per test case.",
    )
    parser_fuzz.add_argument(
        '-w',
        '--working-directory',
        type=str,
        default='.',
    )
    parser_fuzz.add_argument(
        '-t',
        '--testcase',
        type=str,
        default=None,
        help="Use an existing test case [DEPRECATED - see reproduce]")
    parser_fuzz.add_argument(
        '--timeout',
        type=int,
        default=0,
        help="Run fuzzing with a time limit [seconds]. No timeout when set to zero.")
    parser_fuzz.add_argument(
        '--nonstop', action='store_true', help="Don't stop after detecting an unexpected result")
    parser_fuzz.add_argument(
        '--save-violations',
        type=_arg2bool,
        default=True,
        help="If set, store all detected violations in working directory.",
    )

    # ==============================================================================================
    # 基于模板的模糊测试子命令 - 使用预定义模板生成测试用例
    parser_tfuzz = subparsers.add_parser(
        'tfuzz',
        add_help=True,
        parents=[common_parser],
        formatter_class=ArgumentDefaultsHelpFormatter)
    parser_tfuzz.add_argument(
        "-n",
        "--num-test-cases",
        type=int,
        default=1,
        help="Number of test cases.",
    )
    parser_tfuzz.add_argument(
        "-i",
        "--num-inputs",
        type=int,
        default=100,
        help="Number of inputs per test case.",
    )
    parser_tfuzz.add_argument(
        '-w',
        '--working-directory',
        type=str,
        default='',
    )
    parser_tfuzz.add_argument(
        '-t',
        '--template',
        type=str,
        required=True,
        help="The template to use for generating test cases")
    parser_tfuzz.add_argument(
        '--timeout',
        type=int,
        default=0,
        help="Run fuzzing with a time limit [seconds]. No timeout when set to zero.")
    parser_tfuzz.add_argument(
        '--nonstop', action='store_true', help="Don't stop after detecting an unexpected result")
    parser_tfuzz.add_argument(
        '--save-violations',
        type=_arg2bool,
        default=True,
        help="If set, store all detected violations in working directory.",
    )

    # ==============================================================================================
    # 追踪分析子命令 - 独立分析合约追踪与硬件追踪的差异
    parser_analyser = subparsers.add_parser(
        'analyse',
        add_help=True,
        parents=[common_parser],
        formatter_class=ArgumentDefaultsHelpFormatter)
    parser_analyser.add_argument(
        '--ctraces',
        type=str,
        required=True,
    )
    parser_analyser.add_argument(
        '--htraces',
        type=str,
        required=True,
    )

    # ==============================================================================================
    # 违规重现子命令 - 重新执行检测到违规的测试用例以确认结果
    parser_reproduce = subparsers.add_parser(
        'reproduce',
        add_help=True,
        parents=[common_parser],
        formatter_class=ArgumentDefaultsHelpFormatter)
    parser_reproduce.add_argument(
        '-t',
        '--testcase',
        type=str,
        default=None,
        required=True,
        help="Path to the test case",
    )
    parser_reproduce.add_argument(
        '-i',
        '--inputs',
        type=str,
        nargs='*',
        default=None,
        help="Path to the directory with inputs")
    parser_reproduce.add_argument(
        "-n",
        "--num-inputs",
        type=int,
        default=100,
        help="Number of inputs per test case. [IGNORED if --inputs is set]",
    )

    # ==============================================================================================
    # 测试用例最小化子命令 - 通过多轮简化缩小违规测试用例规模
    parser_mini = subparsers.add_parser(
        'minimize',
        add_help=True,
        parents=[common_parser],
        help="Minimize a test case by executing a series of minimization passes. "
        "The set of passes is controlled via CLI arguments.",
        formatter_class=ArgumentDefaultsHelpFormatter)
    parser_mini.add_argument(
        '--testcase',
        '-t',
        type=str,
        required=True,
        help="Path to the test case program that needs to be minimized.",
    )
    parser_mini.add_argument(
        "-i",
        "--num-inputs",
        type=int,
        required=True,
        help="Number of inputs to the program that will be used during minimization.",
    )
    parser_mini.add_argument(
        '--testcase-outfile',
        '-o',
        type=str,
        required=True,
        help="Output path for the minimized test case program.",
    )
    parser_mini.add_argument(
        '--input-outdir',
        type=str,
        default=None,
        help="Output directory for storing minimized inputs.",
    )
    parser_mini.add_argument(
        '--num-attempts',
        type=int,
        default=1,
        help="Number of attempts to minimize the test case.",
    )
    # 以下为各最小化 pass 的开关参数
    parser_mini.add_argument(
        '--enable-instruction-pass',
        type=_arg2bool,
        default=True,
        help="Enable the instruction minimization pass that iteratively removes "
        "instructions while preserving the violation.",
    )
    parser_mini.add_argument(
        '--enable-simplification-pass',
        type=_arg2bool,
        default=False,
        help="Enable the instruction simplification pass that replaces complex "
        "instructions with simpler ones while preserving the violation.",
    )
    parser_mini.add_argument(
        '--enable-nop-pass',
        type=_arg2bool,
        default=False,
        help="Enable the NOP replacement pass that replaces instructions with NOPs "
        "while preserving the violation.",
    )
    parser_mini.add_argument(
        '--enable-constant-pass',
        type=_arg2bool,
        default=False,
        help="Enable the constant simplification pass that replaces constants with 0s "
        "while preserving the violation.",
    )
    parser_mini.add_argument(
        '--enable-mask-pass',
        type=_arg2bool,
        default=False,
        help="Enable the mask simplification pass that reduces the size of instrumentation "
        "masks while preserving the violation.",
    )
    parser_mini.add_argument(
        '--enable-label-pass',
        type=_arg2bool,
        default=True,
        help="Enable the label removal pass that removes unused labels from the assembly file.",
    )
    parser_mini.add_argument(
        '--enable-fence-pass',
        type=_arg2bool,
        default=False,
        help="Enable the fence insertion pass that adds LFENCEs after instructions "
        "while preserving the violation.",
    )
    parser_mini.add_argument(
        "--enable-input-seq-pass",
        type=_arg2bool,
        default=False,
        help="Enable the input sequence minimization pass that removes inputs from "
        "the original generated sequence while preserving the violation.",
    )
    parser_mini.add_argument(
        "--enable-input-diff-pass",
        type=_arg2bool,
        default=False,
        help="Enable the violating input difference minimization pass that removes "
        "inputs that do not contribute to the violation.",
    )
    parser_mini.add_argument(
        "--enable-comment-pass",
        type=_arg2bool,
        default=False,
        help="Enable the violation comment pass that adds comments to the assembly file "
        "with details about the violation.",
    )

    # ==============================================================================================
    # 测试用例生成子命令 - 独立生成测试用例（不运行模糊测试）
    parser_generator = subparsers.add_parser(
        'generate',
        add_help=True,
        parents=[common_parser],
        formatter_class=ArgumentDefaultsHelpFormatter)
    parser_generator.add_argument(
        "-r",
        "--seed",
        type=int,
        default=0,
        help="Add seed to generate test case.",
    )
    parser_generator.add_argument(
        "-n",
        "--num-test-cases",
        type=int,
        default=5,
        help="Number of test cases.",
    )
    parser_generator.add_argument(
        "-i",
        "--num-inputs",
        type=int,
        default=100,
        help="Number of inputs per test case.",
    )
    parser_generator.add_argument(
        '-w',
        '--working-directory',
        type=str,
        default='',
    )
    parser_generator.add_argument(
        '--permit-overwrite',
        action='store_true',
    )

    # ==============================================================================================
    # ISA 规范下载子命令 - 下载指定架构的指令集规范文件
    parser_get_isa = subparsers.add_parser('download_spec', add_help=True)
    parser_get_isa.add_argument("-a", "--architecture", type=str, required=True)
    parser_get_isa.add_argument(
        '--outfile',
        '-o',
        type=str,
        required=True,
    )
    parser_get_isa.add_argument("--extensions", nargs="*", default=[])
    return parser.parse_args()


def main() -> int:  # pylint: disable=r0911,r0912,r0915  # this function is necessarily complex
    """
    解析命令行参数并启动相应模式的模糊测试器。

    本函数是 CLI 的核心入口，根据子命令类型执行以下操作：
    - fuzz/tfuzz: 启动模糊测试循环
    - reproduce: 重现已检测到的违规
    - generate: 独立生成测试用例
    - analyse: 分析追踪文件
    - minimize: 最小化测试用例
    - download_spec: 下载 ISA 规范

    返回:
        退出码（0 表示成功，1 表示错误）
    """
    args = _parse_args()

    # 更新配置 - 加载 YAML 配置文件，并在使用现有测试用例时禁用随机生成
    if getattr(args, 'config', None):
        CONF.load(args.config, args.include_dir)
    if getattr(args, 'testcase', None):
        CONF.disable_generation()
    update_logging_after_config_change()

    # 检查文件和目录参数是否有效
    if getattr(args, 'testcase', None) and not os.path.isfile(args.testcase):
        print("[ERROR]", f"The test case file `{args.testcase}` does not exist")
        return 1
    if getattr(args, 'working_directory', None) and not os.path.isdir(args.working_directory):
        print("[ERROR]", f"The working directory `{args.working_directory}` does not exist")
        return 1
    if (getattr(args, 'enable_input_seq_pass', None)
        or getattr(args, 'enable_input_diff_pass', None)) \
            and not args.input_outdir:
        print(
            "[ERROR]", "Passes --enable-input-seq-pass and --enable-input-diff-pass "
            "require flag --input-outdir to be set.")
        return 1

    # 强制 Unicorn 版本检查：新版本 Unicorn 存在导致模糊测试误报的 bug，
    # 这是临时解决方案，直到该 bug 被修复
    if unicorn.__version__ != '1.0.3' and CONF.instruction_set == 'x86-64':  # type: ignore
        print(
            "[ERROR]", "The fuzzer requires Unicorn version 1.0.3. Please install it using "
            "`pip install unicorn==1.0.3`.")
        return 1

    # 模糊测试模式 - 根据子命令类型选择模糊测试策略
    if args.subparser_name in ('fuzz', 'tfuzz'):
        testcase = args.testcase if args.subparser_name == 'fuzz' else args.template
        fuzzer = get_fuzzer(args.instruction_set, args.working_directory, testcase, None)
        type_: FuzzingMode
        if args.subparser_name == 'tfuzz':
            type_ = 'template'       # 基于模板的模糊测试
        elif testcase:
            type_ = 'asm'            # 使用已有汇编测试用例
        else:
            type_ = 'random'         # 随机生成测试用例
        exit_code = fuzzer.start(
            args.num_test_cases,
            args.num_inputs,
            args.timeout,
            args.nonstop,
            args.save_violations,
            type_=type_)
        return exit_code

    # 违规重现模式 - 重新执行检测到违规的测试用例以确认结果
    if args.subparser_name == 'reproduce':
        fuzzer = get_fuzzer(args.instruction_set, "", args.testcase, args.inputs)
        exit_code = fuzzer.start(1, args.num_inputs, 0, False, False, type_='asm')
        return exit_code

    # 独立测试用例生成模式 - 仅生成测试用例，不运行模糊测试
    if args.subparser_name == "generate":
        fuzzer = get_fuzzer(args.instruction_set, args.working_directory, "", None)
        fuzzer.standalone_generate(args.seed, args.num_test_cases, args.num_inputs,
                                   args.permit_overwrite)
        return 0

    # 追踪分析模式 - 独立分析合约追踪与硬件追踪
    if args.subparser_name == 'analyse':
        fuzzer = get_fuzzer(args.instruction_set, "", "", None)
        fuzzer.standalone_analyse(args.ctraces, args.htraces)
        return 0

    # 测试用例最小化模式 - 执行多轮简化 pass 缩小违规测试用例规模
    if args.subparser_name == "minimize":
        if (args.enable_input_seq_pass or args.enable_input_diff_pass) and not args.input_outdir:
            raise SystemExit("ERROR: Passes --enable-input-seq-pass and --enable-input-diff-pass \n"
                             "require flag --input_outdir to be set.")

        fuzzer = get_fuzzer(args.instruction_set, "", args.testcase, None)
        minimizer = get_minimizer(fuzzer, args.instruction_set)
        minimizer.run(
            test_case_asm=args.testcase,
            n_inputs=args.num_inputs,
            test_case_outfile=args.testcase_outfile,
            input_outdir=args.input_outdir,
            n_attempts=args.num_attempts,
            enable_instruction_pass=args.enable_instruction_pass,
            enable_simplification_pass=args.enable_simplification_pass,
            enable_nop_pass=args.enable_nop_pass,
            enable_constant_pass=args.enable_constant_pass,
            enable_mask_pass=args.enable_mask_pass,
            enable_label_pass=args.enable_label_pass,
            enable_fence_pass=args.enable_fence_pass,
            enable_input_seq_pass=args.enable_input_seq_pass,
            enable_input_diff_pass=args.enable_input_diff_pass,
            enable_comment_pass=args.enable_comment_pass,
        )
        return 0

    # ISA 规范下载模式 - 下载指定架构的指令集规范文件
    if args.subparser_name == "download_spec":
        get_downloader(args.architecture, args.extensions, args.outfile).run()  # type: ignore
        return 0

    print("[ERROR]", "Invalid subcommand")
    return 1


if __name__ == '__main__':
    print("[ERROR]", "This file is not meant to be run directly. Use `revizor.py` instead.")
    sys.exit(1)
