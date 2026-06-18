// ARM64 Spectre V1测试(ARM64版)：条件分支误预测的侧信道泄漏
// 测试目标：验证ARM64上Spectre V1(Bounds Check Bypass)的侧信道泄漏检测
//
// 测试场景：
//   - 输入x0包含秘密数据(超出数组边界)
//   - 输入x1作为条件判断值
//   - 分支预测器误预测b.eq路径，导致投机执行越界LDR
//   - 投机执行的LDR将秘密数据加载到缓存
//   - 通过Prime+Probe/Flush+Reload检测缓存残留痕迹
//
// ARM64与x86的关键差异：
//   - ARM64使用CMP+B.EQ而非CMP+JE
//   - ARM64使用x20作为MEMORY_BASE_REGISTER(而非x86的r14)
//   - ARM64使用LDR而非MOV来读取内存
//   - ARM64的分支误预测恢复路径不同(ISB冲刷流水线)
//
// 验证要点：
//   1. 分支误预测确实触发投机执行
//   2. 投机LDR的缓存痕迹可以被PMU检测(L1D_CACHE_REFILL)
//   3. INST_SPEC > INST_RETIRED(投机指令数>完成指令数)

.section .data.main
.function_main:

    // 减少x0的熵，使其作为数组偏移
    and x0, x0, #0b111111000000

    // 延迟条件判断，增加误预测概率
    add x1, x1, x0
    add x1, x1, #1
    add x1, x1, x0
    add x1, x1, #1
    add x1, x1, x0
    add x1, x1, #1
    add x1, x1, x0
    add x1, x1, #1
    add x1, x1, x0
    add x1, x1, #1
    add x1, x1, x0
    add x1, x1, #1
    add x1, x1, x0
    add x1, x1, #1

    // 减少x1的熵
    and x1, x1, #0b1000000

    // 条件分支：如果x1==0则跳到安全路径
    cmp x1, #0
    b.eq .l1

.l0:
    // x1 != 0路径(可能被误预测)
    // 越界内存访问：x0可能超出数组范围
    add x2, x20, x0
    ldr x0, [x2]
    b .l2

.l1:
    // x1 == 0路径(安全路径，不执行越界访问)
    nop

.l2:

.test_case_exit:
