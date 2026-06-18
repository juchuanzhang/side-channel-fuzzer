// ARM64 SET_DATA_PERMISSIONS测试：动态修改PTE权限触发故障
// 测试目标：验证MACRO_SET_DATA_PERMISSIONS宏在ARM64上正确修改PTE权限位
//
// 测试场景：
//   - main actor在测量开始后修改faulty_area的PTE权限
//   - 使faulty_area变为不可读(清除PTE的Read位)
//   - 然后访问faulty_area，触发Data Abort
//   - fault_handler捕获异常并恢复
//
// 验证要点：
//   1. SET_DATA_PERMISSIONS宏正确修改ARM64 PTE位
//   2. MODIFIABLE_PTE_BITS在ARM64上包含正确的位(Valid/AP/PXN/XN)
//   3. PTE修改后TLB刷新使修改立即生效
//   4. 异常触发后htrace正确记录缓存状态

.section .data.main
.function_start:
    .macro.measurement_start:

    // 动态修改faulty_area的PTE权限——使faulty_area不可读
    // args格式: arg1=actor_id, arg2=0, arg3=mask_set, arg4=mask_clear
    // ARM64 PTE: 清除Valid位(S1_PTE_VALID=bit0)或清除AP的Read位
    .macro.set_data_permissions:

    // 访问faulty_area——如果PTE被正确修改，将触发Data Abort
    ldr x0, [x20, #0x2000]

    .macro.measurement_end:

    // 正常路径
    b .normal

    // 异常着陆点
    .macro.fault_handler:

.normal:
    nop

.test_case_exit:
