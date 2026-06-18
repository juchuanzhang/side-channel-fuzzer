// ARM64 K2U域切换测试：内核(EL1)→用户(EL0)特权级切换
// 测试目标：验证K2U宏(eret从EL1到EL0)和U2K宏(svc从EL0到EL1)的正确性
//
// 测试场景：
//   - main actor(host kernel)通过K2U切换到actor2(host user)
//   - actor2在EL0执行内存访问(LDR)，收集侧信道痕迹
//   - actor2通过U2K切换回main actor
//   - main actor继续执行并返回
//
// 验证要点：
//   1. eret后处理器确实在EL0执行(SPSR_EL1.M=EL0t)
//   2. svc #0后处理器确实回到EL1
//   3. EL0可以正确访问沙箱内存(x20指向data区)
//   4. VBAR_EL1正确指向inner_vector_table捕获SVC

.section .data.main
.function_start:
    // 初始化x0，用于传递数据到actor2
    mov x0, #1

    // 设置K2U目标：actor2的function_1
    .macro.set_k2u_target.actor2.function_1:
    // 执行K2U切换：EL1→EL0
    .macro.switch_k2u.actor2:

.function_fin:
    // K2U着陆点：U2K返回后从这里继续
    .macro.landing_u2k:
    nop

.section .data.actor2
.function_1:
    // K2U着陆点：从EL1切换到EL0后从这里开始
    .macro.landing_k2u:

    // EL0代码：执行侧信道敏感操作
    // mask地址，避免越界
    and x0, x0, #0b111111000000
    // 从沙箱数据区加载——这是侧信道泄漏的核心操作
    ldr x1, [x20, x0]

    // 设置U2K返回目标：main的function_fin
    .macro.set_u2k_target.main.function_fin:
    // 执行U2K切换：EL0→EL1
    .macro.switch_u2k.main:

.test_case_exit:
