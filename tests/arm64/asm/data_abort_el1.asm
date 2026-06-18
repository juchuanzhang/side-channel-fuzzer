// ARM64异常测试：数据访问故障(Data Abort)触发和恢复
// 测试目标：验证EL0和EL1下的数据异常(Data Abort)能否被fault_handler正确捕获
//
// 测试场景1(EL1 fault)：
//   - main actor在EL1执行对faulty_area的受限访问
//   - 触发数据异常(Permission Fault/Translation Fault)
//   - fault_handler捕获异常，恢复执行流
//
// 测试场景2(EL0 fault)：
//   - main actor通过K2U切换到actor2(EL0)
//   - actor2尝试执行对faulty_area的受限访问
//   - 触发Data Abort from EL0(ESR_EL1.EC=0x24)
//   - inner_vector_table捕获SVC/Data Abort，恢复到EL1
//
// 验证要点：
//   1. ESR_EL1.EC=0x24(Data Abort from lower EL)正确识别
//   2. FAR_EL1记录正确的故障地址
//   3. fault_handler在EL1/EL0下都能正确恢复执行流
//   4. 测量宏在异常恢复后正确记录htrace

.section .data.main
.function_start:
    .macro.measurement_start:

    // EL1异常测试：访问faulty_area中的受限地址
    // faulty_area的PTE权限在每次测量迭代中被动态修改
    // 如果PTE被设置为不可读，此LDR将触发Data Abort
    ldr x0, [x20, #0x2000]  // faulty_area偏移(FAULTY_AREA_OFFSET)

    .macro.measurement_end:

    // 正常执行路径(如果faulty_area可读)
    b .normal_exit

    // 异常着陆点(如果触发Data Abort)
    .macro.fault_handler:
    // fault_handler恢复后继续执行
    // 此时htrace已经记录了异常前的缓存访问模式

.normal_exit:
    nop

.test_case_exit:
