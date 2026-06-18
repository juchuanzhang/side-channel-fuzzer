// ARM64 H2G+异常组合测试：guest actor触发Stage-2 Translation Fault
// 测试目标：验证H2G切换后guest actor触发Stage-2异常，由outer_vector_table捕获
//
// 测试场景：
//   - main actor(EL2 host)通过H2G切换到actor2(EL1 guest)
//   - actor2(guest)尝试访问未映射的IPA地址
//   - 触发Stage-2 Translation Fault(ESR_EL2.EC=0x24, ISS.FSC=0x04-0x07)
//   - outer_vector_table(EL2)捕获异常
//   - host恢复执行
//
// 验证要点：
//   1. Stage-2 Translation Fault被outer_vector_table捕获
//   2. ESR_EL2.EC=0x24(Data Abort from lower EL)正确识别
//   3. HPFAR_EL2记录Stage-2故障的IPA地址
//   4. HCR_EL2.VM=1期间Stage-2翻译启用
//   5. 异常恢复后hvc能正确返回EL2

.section .data.main
.function_main1:
    // 设置H2G目标
    .macro.set_h2g_target.actor2.function_a2:
    .macro.set_g2h_target.main.function_fin:
    .macro.switch_h2g.actor2:

.function_fin:
    .macro.landing_g2h:
    nop

.section .data.actor2
.function_a2:
    .macro.landing_h2g:
    .macro.measurement_start:

    // guest代码：访问faulty_area——可能触发Stage-2 Translation Fault
    // 如果S2PT PTE被设置为无效(V=0)，此LDR触发Translation Fault from Stage-2
    ldr x0, [x20, #0x2000]  // faulty_area偏移

    .macro.measurement_end:

    // 如果没有异常，正常返回
    .macro.switch_g2h.main:

.test_case_exit:
