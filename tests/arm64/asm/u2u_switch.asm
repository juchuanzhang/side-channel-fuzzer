// ARM64 U2U跨域测试：两个用户态actor通过K2U/U2K切换
// 测试目标：验证两个EL0 actor之间的完整切换流程
//
// 测试场景：
//   - main actor(host kernel)通过K2U切换到actor2(host user EL0)
//   - actor2在EL0执行侧信道操作，然后通过U2K回到EL1
//   - main actor再次通过K2U切换到actor3(host user EL0)
//   - actor3在EL0执行不同地址的侧信道操作，然后通过U2K回到EL1
//   - main actor完成并返回
//
// 验证要点：
//   1. 多次K2U/U2K切换的正确性(两次完整切换周期)
//   2. 不同actor的EL0栈和数据区不互相干扰
//   3. VBAR_EL1在每次K2U前正确设置
//   4. SPSR_EL1在每次eret前正确配置为EL0t

.section .data.main
.function_start:
    mov x0, #1
    // 第一次K2U：切换到actor2
    .macro.set_k2u_target.actor2.function_1:
    .macro.switch_k2u.actor2:

.function_phase2:
    // actor2返回后，准备第二次K2U
    .macro.landing_u2k:
    mov x0, #2
    // 第二次K2U：切换到actor3
    .macro.set_k2u_target.actor3.function_3:
    .macro.switch_k2u.actor3:

.function_fin:
    // actor3返回后，测试完成
    .macro.landing_u2k:
    nop

.section .data.actor2
.function_1:
    .macro.landing_k2u:
    // actor2(EL0)：访问偏移0x100处的数据
    and x0, x0, #0b111111000000
    ldr x1, [x20, x0]
    // 回到main
    .macro.set_u2k_target.main.function_phase2:
    .macro.switch_u2k.main:

.section .data.actor3
.function_3:
    .macro.landing_k2u:
    // actor3(EL0)：访问偏移0x200处的数据
    and x0, x0, #0b111111000000
    ldr x2, [x20, x0]
    // 回到main
    .macro.set_u2k_target.main.function_fin:
    .macro.switch_u2k.main:

.test_case_exit:
