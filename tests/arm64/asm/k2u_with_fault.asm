// ARM64 K2U+异常组合测试：用户态actor触发Data Abort
// 测试目标：验证K2U切换后EL0 actor触发异常，由inner_vector_table捕获并恢复
//
// 测试场景：
//   - main actor(EL1)通过K2U切换到actor2(EL0)
//   - actor2(EL0)尝试访问faulty_area受限页面
//   - 触发Data Abort from EL0(ESR_EL1.EC=0x24)
//   - inner_vector_table捕获异常，恢复到EL1
//   - main actor继续正常执行
//
// 验证要点：
//   1. EL0的Data Abort被inner_vector_table正确捕获
//   2. ESR_EL1.EC=0x24被正确解码
//   3. FAR_EL1记录正确的故障地址(actor2的faulty_area)
//   4. 异常恢复后SVC能正确返回EL1
//   5. VBAR_EL1在K2U切换前后正确设置

.section .data.main
.function_start:
    .macro.measurement_start:

    // 设置K2U目标：actor2的function_1
    .macro.set_k2u_target.actor2.function_1:
    // 执行K2U切换
    .macro.switch_k2u.actor2:

.function_fin:
    // actor2返回(通过异常恢复+SVC)后继续
    .macro.landing_u2k:
    .macro.measurement_end:
    nop

.section .data.actor2
.function_1:
    .macro.landing_k2u:
    .macro.measurement_start:

    // EL0代码：访问faulty_area——可能触发Data Abort
    // 如果PTE被设置为不可读，此LDR触发Permission Fault from EL0
    ldr x0, [x20, #0x2000]  // faulty_area偏移

    .macro.measurement_end:

    // 如果没有异常，正常返回
    .macro.set_u2k_target.main.function_fin:
    .macro.switch_u2k.main:

.test_case_exit:
