// ARM64 V2V跨域测试：两个guest actor通过H2G/G2H切换
// 测试目标：验证两个guest(VM) actor之间的完整切换流程
//
// 测试场景：
//   - main actor(host hypervisor)通过H2G切换到actor2(guest)
//   - actor2在guest模式执行侧信道操作，通过G2H回到host
//   - main actor通过H2G切换到actor3(guest)
//   - actor3在guest模式执行侧信道操作，通过G2H回到host
//   - main actor完成并返回
//
// 验证要点：
//   1. 多次H2G/G2H切换的正确性(VTTBR_EL2在每次切换时正确更新)
//   2. 不同guest actor的S2PT地址空间隔离(ASID不同)
//   3. ESR_EL2正确识别每次hvc退出
//   4. guest在两次eret间不会残留上一个guest的TLB条目
//   5. SPSR_EL2/ELR_EL2在每次H2G前正确配置

.section .data.main
.function_main1:
    // 第一次H2G：切换到actor2(guest)
    .macro.set_h2g_target.actor2.function_a2:
    .macro.set_g2h_target.main.function_phase2:
    .macro.switch_h2g.actor2:

.function_phase2:
    // actor2返回后，准备第二次H2G
    .macro.landing_g2h:
    // 第二次H2G：切换到actor3(guest)
    .macro.set_h2g_target.actor3.function_a3:
    .macro.set_g2h_target.main.function_fin:
    .macro.switch_h2g.actor3:

.function_fin:
    .macro.landing_g2h:
    nop

.section .data.actor2
.function_a2:
    .macro.landing_h2g:
    .macro.measurement_start:
    // guest actor2：访问沙箱数据
    and x0, x0, #0b111111000000
    ldr x1, [x20, x0]
    .macro.measurement_end:
    // 回到host
    .macro.switch_g2h.main:

.section .data.actor3
.function_a3:
    .macro.landing_h2g:
    .macro.measurement_start:
    // guest actor3：访问不同偏移的沙箱数据
    and x0, x0, #0b111111000000
    ldr x2, [x20, x0]
    .macro.measurement_end:
    // 回到host
    .macro.switch_g2h.main:

.test_case_exit:
