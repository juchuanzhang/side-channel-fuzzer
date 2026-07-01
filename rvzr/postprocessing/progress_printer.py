"""
文件：最小化进度打印器。

该模块提供了一个简单的进度打印类，用于在终端中显示最小化过程的进度。
确保所有最小化pass提供统一的输出格式，包括：
- pass编号和名称
- 进度条（成功用"."表示，失败用"-"表示）
- pass结果消息
- 全局信息消息

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""


class ProgressPrinter():
    """
    最小化进度打印器——在终端中打印最小化进度。
    用于确保所有最小化pass提供统一的输出格式。

    进度符号：
    - "." 表示成功（修改通过验证）
    - "-" 表示失败（修改未通过验证）
    """
    line_width: int = 64  # 每行进度符号数量
    curr_width: int = 0   # 当前行的进度符号数量
    offset: int = 2       # 文本缩进偏移量
    pass_id: int = 0      # 当前pass编号
    progress_bar_on: bool = False  # 是否正在显示进度条

    def pass_start(self, label: str, offset: int = 2) -> None:
        """ 开始一个新的最小化pass，打印pass编号和名称 """
        self.pass_id += 1
        self.offset = offset
        self.curr_width = 0
        self.progress_bar_on = False
        print(f"[PASS {self.pass_id}] {label}", flush=True)

    def pass_finish(self) -> None:
        """ 结束当前最小化pass，换行结束进度条 """
        print("")  # finish the line

    def pass_msg(self, msg: str) -> None:
        """ 打印与当前pass相关的消息 """
        print(" " * self.offset + "> " + msg)
        self.progress_bar_on = False

    def next(self, success: bool) -> None:
        """
        打印一个进度符号。
        :param success: True打印"."（成功），False打印"-"（失败）
        """
        if not self.progress_bar_on:
            print("")
            self.progress_bar_on = True

        self.curr_width += 1
        if self.curr_width > self.line_width:  # 超过行宽时换行
            print("\n", end="", flush=True)
            self.curr_width = self.offset

        if success:
            print(".", end="", flush=True)  # 成功
        else:
            print("-", end="", flush=True)  # 失败

    def global_msg(self, msg: str) -> None:
        """ 打印与当前pass无关的全局信息消息 """
        print(f"[INFO] {msg}")