from barf.barf import BARF
import angr
import pyvex
import claripy
import struct
import os


# 返回cfg中的块分类后的结构
def classify_blocks(cfg, start):
    # 序言块的地址就是函数的起始地址
    prologue = start
    # 主分发块是序言块的后继
    main_dispatcher = cfg.find_basic_block(start).direct_branch

    ret_block = pre_dispatcher = None
    for block in cfg.basic_blocks:
        # 返回块无后继节点
        if len(block.branches) == 0 and block.direct_branch == None:
            ret_block = block.start_address
        # 预分发器的后继是主分发器
        elif block.direct_branch == main_dispatcher:
            pre_dispatcher = block.start_address
    assert(ret_block is not None)
    assert(pre_dispatcher is not None)

    relevant_blocks = []
    nop_blocks = []
    for block in cfg.basic_blocks:
        # 真实块的后继是预分发器 只留下含有多于一条指令的真实块
        if block.direct_branch == pre_dispatcher and len(block.instrs) > 1:
            relevant_blocks.append(block.start_address)
        # 其他的为子分发器
        elif block.start_address != prologue and block.start_address != ret_block:
            nop_blocks.append(block)
    return prologue, main_dispatcher, ret_block, pre_dispatcher, relevant_blocks, nop_blocks


def symbolic_execution(project, relevant_block_addrs, start_addr, hook_addrs=None, modify_value=None, inspect=False):

    # 不执行被hook的指令，转而执行下面的代码
    def retn_procedure(state):
        # 求解此时的rip寄存器的值，并取消hook
        ip = state.solver.eval(state.regs.ip)
        project.unhook(ip)
        return

    def statement_inspect(state):
        expressions = list(
            state.scratch.irsb.statements[state.inspect.statement].expressions)
        # angr使用的是vex的IR, 遇到ITE的IR表达式，修改临时变量的值来实现走哪个分支
        # ITE:   x = ITE(cond, case1, case2)
        if len(expressions) != 0 and isinstance(expressions[0], pyvex.expr.ITE):
            state.scratch.temps[expressions[0].cond.tmp] = modify_value
            state.inspect._breakpoints['statement'] = []

    if hook_addrs is not None:
        # 注册hook，在执行到hook_addr时不执行执行，转而执行 retn_procedure
        for hook_addr in hook_addrs:
            project.hook(hook_addr, retn_procedure, length=5)

    # 创建一个空程序状态，从start_addr开始运行
    state = project.factory.blank_state(addr=start_addr, remove_options={
                                        angr.sim_options.LAZY_SOLVES})
    if inspect:
        # 插入断点，每次运行指令前执行 statement_inspect
        state.inspect.b(
            'statement', when=angr.state_plugins.inspect.BP_BEFORE, action=statement_inspect)
    sm = project.factory.simulation_manager(state)
    # step每次执行完一个BasicBlock
    sm.step()
    while len(sm.active) > 0:
        for active_state in sm.active:
            if active_state.addr in relevant_block_addrs:
                return active_state.addr
        sm.step()

    return None


def fill_nop(data, start, end):
    global opcode
    for i in range(start, end):
        data[i] = opcode['nop'][0]


def fill_jmp_offset(data, start, offset):
    jmp_offset = struct.pack('<i', offset)
    for i in range(4):
        data[start + i] = jmp_offset[i]


if __name__ == '__main__':
    # x86 opcode
    opcode = {'a':b'\x87', 'ae': b'\x83', 'b':b'\x82', 'be':b'\x86', 'c':b'\x82', 'e':b'\x84', 'z':b'\x84', 'g':b'\x8F',
              'ge':b'\x8D', 'l':b'\x8C', 'le':b'\x8E', 'na':b'\x86', 'nae':b'\x82', 'nb':b'\x83', 'nbe':b'\x87', 'nc':b'\x83',
              'ne':b'\x85', 'ng':b'\x8E', 'nge':b'\x8C', 'nl':b'\x8D', 'nle':b'\x8F', 'no':b'\x81', 'np':b'\x8B', 'ns':b'\x89',
              'nz':b'\x85', 'o':b'\x80', 'p':b'\x8A', 'pe':b'\x8A', 'po':b'\x8B', 's':b'\x88', 'nop':b'\x90', 'jmp':b'\xE9', 'j':b'\x0F'}
    # filename = "E:\\GCSJ\\check_pwd_fla.exe"
    # start = 0x406D10
    # length = 0x2E1
    filename = "E:\\GCSJ\\check_pwd_fla.exe"
    start = 0x140006CD0
    length = 0x31E

    barf = BARF(filename)
    base_addr = barf.binary.entry_point >> 12 << 12
    project = angr.Project(filename, load_options={'auto_load_libs': False})
    # binary 的控制流图
    cfg = barf.recover_cfg(start=start)
    blocks = cfg.basic_blocks
    # 将函数的BB进行分类
    prologue, main_dispatcher, ret_block, pre_dispatcher, relevant_blocks, nop_blocks = classify_blocks(cfg, start)
    print('*******************relevant blocks************************')
    print('prologue:%#x' % start)
    print('main_dispatcher:%#x' % main_dispatcher)
    print('pre_dispatcher:%#x' % pre_dispatcher)
    print('retn:%#x' % ret_block)
    print('relevant_blocks:', [hex(addr) for addr in relevant_blocks])

    print('*******************symbolic execution*********************')
    relevants = relevant_blocks
    relevants.append(prologue)
    relevants_without_retn = list(relevants)
    relevants.append(ret_block)
    flow = {}
    for parent in relevants:
        flow[parent] = []
    modify_value = None
    patch_instrs = {}
    for relevant in relevants_without_retn:
        print('-------------------dse %#x---------------------' % relevant)
        block = cfg.find_basic_block(relevant)
        has_branches = False
        hook_addrs = set([])
        for ins in block.instrs:
            # 块中存在cmov条件传送指令，则存在两个后继分支，且后续需要打补丁
            if ins.mnemonic.startswith('cmov'):
                patch_instrs[relevant] = ins
                has_branches = True
            # hook call指令，使其不运行
            elif ins.mnemonic.startswith('call'):
                hook_addrs.add(ins.address)
        #  使用符号执行得到后继分支的地址
        if has_branches:
            # claripy.BVV(1, 1) 和 claripy.BVV(0, 1) 是BitVector，用来决定在条件传送时走那个分支
            flow[relevant].append(symbolic_execution(project, relevants, relevant, hook_addrs, claripy.BVV(1, 1), True))
            flow[relevant].append(symbolic_execution(project, relevants, relevant, hook_addrs, claripy.BVV(0, 1), True))
        else:
            flow[relevant].append(symbolic_execution(project, relevants, relevant, hook_addrs))

    print('************************flow******************************')
    for (k, v) in flow.items():
        print('%#x:' % k, [hex(child) for child in v])

    print('************************patch*****************************')
    flow.pop(ret_block)
    origin = open(filename, 'rb')
    origin_data = bytearray(origin.read())
    origin.close()

    splits = os.path.splitext(filename)
    new_filename = splits[0] + "_recovered" + splits[1]
    recovery = open(new_filename, 'wb')
    # 对于自分发器等无用的块，直接填充nop指令
    for nop_block in nop_blocks:
        fill_nop(origin_data, nop_block.start_address - base_addr, nop_block.end_address - base_addr + 1)
    for (parent, childs) in flow.items():
        if len(childs) == 1:
            # 将块最后一条指令修改为jmp xxxxxx, 其中 xxxxx 为后继块的地址相对于块最后一条指令的下一条指令的相对偏移
            last_instr = cfg.find_basic_block(parent).instrs[-1]
            file_offset = last_instr.address - base_addr
            origin_data[file_offset] = opcode['jmp'][0]
            file_offset += 1
            fill_nop(origin_data, file_offset, file_offset + last_instr.size - 1)
            # childs[0] - last_instr.address - 5 计算后继块的地址相对于块最后一条指令的下一条指令的相对偏移
            fill_jmp_offset(origin_data, file_offset, childs[0] - last_instr.address - 5)
        else:
            #
            instr = patch_instrs[parent]
            file_offset = instr.address - base_addr
            fill_nop(origin_data, file_offset, cfg.find_basic_block(parent).end_address - base_addr + 1)
            # 根据cmov的条件构造对应j条件跳转指令, 如cmovne对应jne等等
            origin_data[file_offset] = opcode['j'][0]
            origin_data[file_offset + 1] = opcode[instr.mnemonic[4:]][0]
            # 此处地址计算同上
            fill_jmp_offset(origin_data, file_offset + 2, childs[0] - instr.address - 6)
            file_offset += 6
            # 在打好补丁的j指令后面补一个jmp指令，跳到另一个分支
            origin_data[file_offset] = opcode['jmp'][0]
            fill_jmp_offset(origin_data, file_offset + 1, childs[1] - (instr.address + 6) - 5)
    recovery.write(origin_data)
    recovery.close()
    print('Successful! The recovered file: %s' % new_filename)