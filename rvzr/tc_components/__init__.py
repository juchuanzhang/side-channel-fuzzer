"""
文件：包含测试用例组件（代码和数据）类集合的模块。

File: Module containing a collection of classes that represent components
      of a test case (both code and data).

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# flake8: noqa
# pylint: skip-file

# 导入所有测试用例组件子模块，方便外部直接使用
from .actor import *
from .instruction import *
from .test_case_code import *
from .test_case_data import *
