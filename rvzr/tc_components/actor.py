"""
文件：定义测试用例中参与者（Actor）抽象的类。

Actor代表测试用例中的执行实体，可以是宿主机(host)或客户机(guest)模式，
可以是内核(kernel)或用户(user)特权级别。每个Actor拥有自己的代码段和数据属性，
数据属性通过页表项(PTE)掩码来描述其内存访问权限和特性。

File: Classes defining the actor abstraction.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import Dict, Tuple, Final, Optional, TYPE_CHECKING
from enum import Enum
import random

from ..target_desc import TargetDesc, PTEBitName, PTEBitOffset

if TYPE_CHECKING:
    from ..config import PageConf, PagePropertyName, ActorConf
    from .test_case_code import CodeSection

    _PTEBitValue = bool
    _PTEDescriptor = Dict[PTEBitName, Tuple[PTEBitOffset, _PTEBitValue]]
    _PropertyMap = Dict[PagePropertyName, Tuple[PTEBitName, bool]]

ActorID = int       # 参与者ID类型
ActorName = str     # 参与者名称类型
PTEMask = int       # 页表项掩码类型


class ActorMode(Enum):
    """ 参与者执行模式的枚举类，表示宿主机(host)或客户机(guest)模式。

    Enumeration class representing the execution mode of an actor (host or guest). """
    HOST = 0     # 宿主机模式
    GUEST = 1    # 客户机（虚拟机）模式


class ActorPL(Enum):
    """ 参与者特权级别的枚举类，表示内核(kernel)或用户(user)级别。

    Enumeration class representing the privilege level of an actor (kernel or user). """
    KERNEL = 0   # 内核特权级别
    USER = 1     # 用户特权级别


# ==================================================================================================
# 辅助函数：管理参与者数据属性
# Helper Functions to manage actor data properties
# ==================================================================================================
def _create_pte_mask(pte_descriptor: _PTEDescriptor, page_properties_to_set: PageConf,
                     page_property_to_pte_bit_name: _PropertyMap) -> PTEMask:
    """
    根据参与者的架构无关数据属性，创建架构特定的页表项(PTE)位掩码。
    该掩码由执行器和模型用来设置参与者的页表属性。

    函数接收一个描述目标架构PTE每个位的字典`pte_descriptor`，每个条目将位名称映射到
    包含该位在PTE中的偏移量和默认值的元组。

    函数根据`page_properties_to_set`字典修改默认值，该字典指定页表项的期望属性
    （通常来自config.yaml）。

    由于`page_properties_to_set`中的属性名称可能与`pte_descriptor`中使用的名称不同，
    函数使用`page_property_to_pte_bit_name`映射在两者之间进行转换。

    如果`page_properties_to_set['randomized']`为True，函数会在掩码生成中引入随机性。
    每个位有一定概率被设置为其默认值，概率与不同于默认值的位数成正比。

    :param pte_descriptor: PTE位的默认值字典
    :param page_properties_to_set: 要设置的页属性字典
    :param page_property_to_pte_bit_name: 属性名称到PTE位名称的映射
    :return: 表示PTE属性的位掩码
    :raises: 如果属性字典无效则抛出AssertionError

    Create an architecture-specific page table entry (PTE) bitmask based on the actor's
    architecture-independent data properties. This bitmask is to be used by the executor
    and the model to set page table properties of actors.

    The function takes a dictionary `pte_descriptor` that describes each bit of the PTE for
    the target architecture. Each entry in the dictionary maps a bit name to a tuple containing
    the bit's offset in the PTE and its default value.

    The function modifies the default values based on the `page_properties_to_set` dictionary,
    which specifies the desired properties for the page table entry (this typically originates
    from config.yaml).

    As the names of the properties in `page_properties_to_set` may differ from the names used in
    the `pte_descriptor`, the function uses the `page_property_to_pte_bit_name` mapping to
    translate between the two.

    Optionally, if `page_properties_to_set['randomized']` is True, the function introduces
    randomness in the bitmask generation. Each bit has a chance of being set to its default
    value, with the probability proportional to the number of bits that differ from their
    default values.

    :param pte_descriptor: dictionary of default values for PTE bits
    :param page_properties_to_set: dictionary of page properties to set
    :param page_property_to_pte_bit_name: mapping from property names to PTE bit names
    :return: bitmask representing the PTE properties
    :raises: AssertionError if the properties dictionary is invalid
    """
    # pylint: disable=too-many-locals  # justification: function is complex but clear

    # 获取是否需要随机化
    is_randomized = page_properties_to_set['randomized']

    # 首先，将架构无关的属性转换为架构特定的属性
    # First, translate the architecture-independent properties to architecture-specific ones
    arch_specific_properties: Dict[PTEBitName, bool] = {}
    for property_name, value in page_properties_to_set.items():
        if property_name == 'randomized':
            continue
        assert property_name in page_property_to_pte_bit_name, \
            f"Actor data property {property_name} is not supported on this architecture"
        # 获取PTE位名称和是否反转标志
        bit_name, is_inverted = page_property_to_pte_bit_name[property_name]
        # 如果属性是反转的（例如，"不存在"在PTE中对应"存在"位），则需要反转值
        if is_inverted:
            value = not value
        arch_specific_properties[bit_name] = value

    # 如果需要随机化，计算位被设置为默认值的概率
    # If randomization is requested, calculate the probability of a bit being set to default value
    probability_of_default = 0.0
    if is_randomized:
        # 计算非默认位的数量
        # calculate the number of non-default bits
        count_non_default = 0
        for bit_name in pte_descriptor:
            if pte_descriptor[bit_name][1] != arch_specific_properties[bit_name]:
                count_non_default += 1

        # 概率与非默认位数成正比
        # 使用一个公式将概率映射到大约[0.5, 0.8]的范围，避免过低或过高的概率
        # the probability is proportional to the number of non-default bits
        # we use a formula that maps the probability in the range of roughly [0.5, 0.8] to
        # avoid having too low or too high probabilities
        a = count_non_default
        b = len(pte_descriptor)
        probability_of_default = (a / (a + b)) * 0.5 + 0.5

    # 创建掩码
    # create the mask
    mask: PTEMask = 0
    for bit_name, new_value in arch_specific_properties.items():
        # 从PTE描述符中获取位偏移和默认值
        # get the bit offset and default value from the PTE descriptor
        bit_offset, default_value = pte_descriptor[bit_name]

        # 位的新值要么直接取自属性字典，要么根据概率随机设置为默认值
        # The new value of the bit is either directly taken from the properties dictionary,
        # or it is randomly set to the default value based on the probability calculated above.
        bit_value: int
        if not is_randomized or new_value == default_value:
            bit_value = new_value
        else:
            # 随机决定是否将该位设置为默认值
            set_to_default = random.random() < probability_of_default
            if set_to_default:
                bit_value = default_value
            else:
                bit_value = new_value

        # 在掩码中设置该位
        # now set the bit in the mask
        bit_value = 1 if bit_value else 0
        mask |= bit_value << bit_offset
    return mask


# ==================================================================================================
# 参与者类
# Actor Class
# ==================================================================================================
class Actor:
    """ 测试用例中的参与者类。每个参与者有自己的执行模式、特权级别、名称和数据属性。

    Class representing an actor in a test case. """

    mode: Final[ActorMode]               # 执行模式（宿主机/客户机）
    privilege_level: Final[ActorPL]      # 特权级别（内核/用户）
    name: Final[ActorName]               # 参与者名称
    data_properties: Final[PTEMask]      # 数据页表项(PTE)属性掩码
    data_ept_properties: Final[PTEMask]  # 数据扩展页表项(EPT)属性掩码（用于虚拟机）
    observer: Final[bool]                # 是否为观察者
    is_main: Final[bool]                 # 是否为主参与者

    _code_section: Optional[CodeSection] = None  # 分配给该参与者的代码段

    # ==============================================================================================
    # 构造函数
    # Constructors

    def __init__(self,
                 mode: ActorMode,
                 pl: ActorPL,
                 name: ActorName,
                 data_properties: PTEMask = 0,
                 data_ept_properties: PTEMask = 0,
                 is_observer: bool = False) -> None:
        """
        初始化参与者对象。

        :param mode: 执行模式（HOST或GUEST）
        :param pl: 特权级别（KERNEL或USER）
        :param name: 参与者名称
        :param data_properties: 数据PTE属性掩码，默认为0
        :param data_ept_properties: 数据EPT属性掩码，默认为0
        :param is_observer: 是否为观察者，默认为False
        """
        self.mode = mode
        self.privilege_level = pl
        self.name = name
        self.data_properties = data_properties
        self.data_ept_properties = data_ept_properties
        self.observer = is_observer
        # 名为"main"的参与者被标记为主参与者
        self.is_main = name == "main"

    @classmethod
    def from_dict(cls, actor_dict: ActorConf, target_desc: TargetDesc) -> 'Actor':
        """
        根据属性字典创建参与者对象。

        :param actor_dict: 参与者属性字典（通常来自config.yaml）
        :param target_desc: 目标架构描述对象
        :return: 参与者对象
        :raises: 如果actor_dict格式错误则抛出ValueError

        Create an actor based on a dictionary of actor properties.
        :param actor_dict: dictionary of actor properties
        :param target_desc: target description
        :return: Actor object
        :raises: ValueError if actor_dict is malformed
        """
        # 解析参与者执行模式
        # actor mode of execution
        if actor_dict['mode'] == "host":
            mode = ActorMode.HOST
        elif actor_dict['mode'] == "guest":
            mode = ActorMode.GUEST
        else:
            raise ValueError(f"Invalid actor mode: {actor_dict['mode']}")

        # 解析特权级别
        # privilege level
        if actor_dict['privilege_level'] == "kernel":
            pl = ActorPL.KERNEL
        elif actor_dict['privilege_level'] == "user":
            pl = ActorPL.USER
        else:
            raise ValueError(f"Invalid actor privilege level: {actor_dict['privilege_level']}")

        # 根据配置创建PTE和EPT属性掩码
        # PTE and EPTE properties
        data_properties = _create_pte_mask(
            target_desc.pte_bits,
            actor_dict["data_properties"],
            target_desc.page_property_to_pte_bit_name,
        )
        data_ept_properties = _create_pte_mask(
            target_desc.vm_pte_bits,
            actor_dict["data_ept_properties"],
            target_desc.page_property_to_vm_pte_bit_name,
        )

        # 创建参与者对象
        # create the actor
        return Actor(
            mode,
            pl,
            actor_dict["name"],
            data_properties=data_properties,
            data_ept_properties=data_ept_properties,
            is_observer=actor_dict["observer"],
        )

    @classmethod
    def create_main(cls) -> 'Actor':
        """
        创建具有默认属性的主参与者（宿主机内核模式）。

        :return: 参与者对象

        Create the main actor with default properties.
        :return: Actor object
        """
        return Actor(ActorMode.HOST, ActorPL.KERNEL, "main")

    # ==============================================================================================
    # 公共方法
    # Public methods
    def assign_code_section(self, section: CodeSection) -> None:
        """ 分配代码段给参与者。每个参与者只能分配一个代码段。

        Assign a code section to the actor. """
        assert self._code_section is None, f"Code section already assigned to actor {self.name}"
        self._code_section = section

    def code_section(self) -> CodeSection:
        """ 获取分配给参与者的代码段。

        Get the code section assigned to the actor. """
        assert self._code_section is not None, f"Code section not assigned to actor {self.name}"
        return self._code_section

    def get_id(self) -> ActorID:
        """
        获取参与者ID。参与者ID由其代码段在ELF文件中的段ID决定。

        :return: 参与者ID
        :raises: 如果ELF段尚未分配则抛出AssertionError

        Get the actor ID.
        :return: actor ID
        :raises: AssertionError if the ELF section has not been assigned
        """
        assert self._code_section is not None, f"Code section not assigned to actor {self.name}"
        assert self._code_section.id_ is not None, \
            "assign_elf_data was not called on the child CodeSection"
        return self._code_section.id_
