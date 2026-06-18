// ARM64 H2G域切换测试：宿主机(EL2)→客户机(EL1 guest)虚拟化切换
// 测试目标：验证H2G宏(eret从EL2到EL1 guest)和G2H宏(hvc从EL1到EL2)的正确性
//
// 测试场景：
//   - main actor(host hypervisor)设置H2G目标并切换到actor2(guest)
//   - actor2在guest模式(EL1)执行内存访问，触发侧信道痕迹
//   - actor2通过G2H切换(hvc #0)回到main actor
//   - main actor继续执行并返回
//
// 验证要点：
//   1. eret后处理器在EL1 guest模式执行(SPSR_EL2.M=EL1h)
//   2. HCR_EL2.VM=1，Stage-2翻译启用
//   3. VTTBR_EL2指向actor2的S2PT
//   4. hvc #0后处理器回到EL2
//   5. ESR_EL2.EC=0x16(HVC64)正确识别退出原因
//   6. guest可以访问沙箱内存(通过S1PT+S2PT两级翻译)

.section .data.main
.function_main1:
    // 设置H2G目标：actor2的function_a2
    .macro.set_h2g_target.actor2.function_a2:
    // 设置G2H返回目标：main的function_fin
    .macro.set_g2h_target.main.function_fin:
    // 执行H2G切换：EL2→EL1 guest
    .macro.switch_h2g.actor2:

.function_fin:
    // G2H着陆点：hvc返回后从这里继续
    .macro.landing_g2h:
    nop

.section .data.actor2
.function_a2:
    // H2G着陆点：eret到guest后从这里开始
    .macro.landing_h2g:
    // 测量开始
    .macro.measurement_start:

    // guest代码：执行侧信道敏感内存访问
    and x0, x0, #0b111111000000
    ldr x1, [x20, x0]

    // 测量结束
    .macro.measurement_end:

    // 执行G2H切换：EL1 guest→EL2 host
    .macro.switch_g2h.main:

.test_case_exit:
