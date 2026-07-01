"""
文件：ARM64指令集规范下载与解析脚本
本脚本负责下载ARM64指令集规范，并将其解析为JSON格式文件，
供测试用例生成器（generator）使用。目前功能尚未完全实现，
仅从测试目录中复制预置的最小规范文件。

File: A script that downloads the ARM64 instruction set
      and parses it into a JSON file that can be used by the generator.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List
import shutil

from rvzr.logs import warning, inform


class Downloader:
    """
    ARM64指令集规范下载器类。
    负责下载ARM64指令集规范并转换为JSON格式。
    目前尚未实现完整的下载功能，仅复制预置的最小规范文件作为替代。

    A class that downloads the ARM64 instruction set and converts it to JSON
    """

    def __init__(self, extensions: List[str], out_file: str) -> None:
        """
        初始化下载器。

        参数:
            extensions: 需要下载的指令集扩展列表（如NEON、SVE等）
            out_file: 输出JSON文件的路径
        """
        self._extensions = extensions
        self._out_file = out_file
        warning(
            "downloader", "The ARM64 spec retrieval is not implemented yet, \n"
            "and this script will just copy a spec file from tests/arm64/min_arm64.json")

    def run(self) -> None:
        """
        运行下载器，将预置的最小ARM64规范文件复制到指定输出路径。
        目前仅执行文件复制操作，真正的下载和解析功能待实现。

        Run the downloader
        """
        shutil.copy("tests/arm64/min_arm64.json", self._out_file)
        inform("downloader", f"ARM64 spec is copied to {self._out_file}")
