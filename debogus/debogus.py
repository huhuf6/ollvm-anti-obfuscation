import angr
import argparse

def split_suffix(filename):
    split = filename.split('.', 1)
    if len(split) > 0:
        return split[0], ''
    return split[0], '.' + split[1]

def write_nops(binary, offset, size):
    for i in range(offset, offset + size):
        binary[i] = 0x90

def write_jmp(binary, offset, jmp_offset):
    jmp_op = b'\xE9'
    jmp_ins = jmp_op + jmp_offset.to_bytes(4,byteorder='little')
    for i in range(5):
        binary[offset] = jmp_ins[i]

class Deboguser:
    
    def __init__(self, filename, start_address, end_address):
        self.proj = angr.Project(filename, load_options={'auto_load_libs': False})  
        # 使用 angr.Project 载入文件，设置 auto_load_libs 为 false 则不加载依赖的 lib
        # 调用的为Project类的构造函数_init_()。Project类是angr模块的主类，它对一个二进制文件进行初始的分析以及参数配置，并将数据存储起来进行后续进一步分析。
        self.filename = filename
        self.start_address = start_address
        self.end_address = end_address
        self.target_blocks = set()  # 目标函数的函数的所有基本块
        self.control_flow = set()  # 目标函数的函数的所有可达块

    def in_function(self, addr):
        return addr >= self.start_address and addr <= self.end_address

    # 获取目标函数的所有基本块
    def load_target_blocks(self):
        cfg = self.proj.analyses.CFGFast()  # Control Flow Graph
        # CFGFast() ,CFG恢复算法,在给定的二进制文件中识别函数，并以非常快的方式构建一个控制流图
        # print("This is the graph:", cfg.graph)
        self.cfg = cfg.functions.get(self.start_address).transition_graph
        for node in self.cfg.nodes():
            # cfg.nodes()中除了会包含函数本身的基本块之外，还会包含函数里调用的其他函数的基本块
            # 把函数中调用的其他函数的基本块筛掉
            if node.addr >= self.start_address and node.addr <= self.end_address:
                self.target_blocks.add(node)

    # CFGAccurate一般都需要提供一个start_state作为起始的状态点进行分析，这就导致分析并不全面。为了获得一个高代码覆盖率的CFG，可以使用CFGFast。
    #
    # CFGFast执行步骤：
    # 函数识别。如果应用程序包含指定函数地址的符号，那么它们也会被用于生成带有函数起始地址的图。此外，代表程序入口点的基本块也会被加入到图中。
    # 递归反编译。递归反编译用于恢复已识别函数的直接跳转。
    # 间接跳转解析。轻量级别名（alias）分析，数据流跟踪，结合预定义策略，被用来解决函数控制流转移。目前CFGFast包括跳转表识别和间接调用目标识别的策略。
    # 快速CFG恢复算法的目标是快速地恢复一个高覆盖率的控制流图，而不关心函数之间的可达性。

    # Hook掉目标函数中调用的所有其他函数
    # 在符号执行一些静态链接的文件时，angr的符号执行模拟器会陷入到复杂的库函数中，
    # 在 angr 中使用 hook 来把指定地址的二进制代码替换为 python 代码。
    # angr 在模拟执行程序时，执行每一条指令前会检测该地址处是否已经被hook
    # 如果是就不执行这条语句，转而执行hook 时指定的 python 处理代码。
    def hook(self):
        function_size = self.end_address - self.start_address + 1
        # project.factory.block( )：用来从给定的地址提取一个基本的代码块
        target_block = self.proj.factory.block(self.start_address,function_size)

        for ins in target_block.capstone.insns:
            if ins.mnemonic == 'call':
                # angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]()
                # 是ReturnUnconstrained类的一个实例，
                # 在符号执行过程中它会返回一个无约束的符号，简单来说就是一个可以返回任何值的函数。
                self.proj.hook(int(ins.op_str, 16), \
                    angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"](), replace=True)

    # 符号执行获取所有可达块
    # 从目标函数开始，simgr.step()逐块执行，一直到没有active状态为止
    # step的过程，每碰到一个跳转就会分裂出两个新的active状态
    # 一边符号执行一边将符号执行能遍历到的所以基本块的地址保存到control_flow中
    def symbolic_execute(self):
        state = self.proj.factory.blank_state \
            ( addr=self.start_address, remove_options={angr.sim_options.LAZY_SOLVES})
        # LAZY_SOLVES: 停止SimRun来检查后继状态的可满足性
        simgr = self.proj.factory.simulation_manager(state)
        # SimulationManager对象用于具体的路径探索
        self.control_flow.add(state.addr)
        while len(simgr.active) > 0:
            for active in simgr.active:
                self.control_flow.add(active.addr)
            simgr.step()

    # 修改不可达块，nop掉没有被执行到的基本块：
    def patch_unreachable_blocks(self, data):
        handled_blocks = set()  # 已经处理过的块
        patched_addrs = []  # nop掉的块的地址
        base_address = self.proj.loader.main_object.mapped_base
        for block in self.target_blocks:  # 遍历目标函数的所有基本块
            if block.addr in handled_blocks:  # 处理过了则跳过
                continue
            handled_blocks.add(block.addr)  # 加入已处理块的列表
            if block.addr in self.control_flow:  # 若是可达块
                for child in self.cfg.successors(block): # 遍历该块的后继块
                    if child.addr < self.start_address or child.addr > self.end_address:
                        continue   # 后继块不在目标函数范围内则跳过
                    if child.addr not in self.control_flow:  # 后继块在目标函数范围且不是可达块
                        handled_blocks.add(child.addr)   # 加入到已处理块的列表
                        patched_addrs.append(hex(child.addr))  # 加入nop块的列表
                        write_nops(data, child.addr - base_address, child.size)  # nop
                        # 把data从child.addr - base_address开始的 child.size个位置改为nop
            else:  # 该基本块不是可达块，也nop掉
                write_nops(data, block.addr - base_address, block.size)
        print(f'Patched {len(patched_addrs)} unreachable blocks: {patched_addrs}')

    # 修改jump指令
    def patch_jump(self, data):
        handled_blocks = set()
        patched_addrs = []
        base_address = self.proj.loader.main_object.mapped_base
        for block in self.target_blocks:
            if block.addr in handled_blocks:
                continue
            handled_blocks.add(block.addr)
            suc = list(self.cfg.successors(block))  # 基本块的后继块列表
            if block.addr in self.control_flow and len(suc) == 2:   
            # 若这个块可达且有两个后继块
                if self.in_function(suc[0].addr) and self.in_function(suc[1].addr):  
                # 两个后继都在目标函数范围内
                    jmp_ins_addr = block.addr + block.size - 6  # jmp跳转指令的地址
                    if suc[0].addr in self.control_flow and suc[1].addr not in self.control_flow:  
                    # 若第一个后继可达，另一个不可达
                        write_nops(data, jmp_ins_addr - base_address, 6)
                        write_jmp(data, jmp_ins_addr - base_address, suc[0].addr - jmp_ins_addr - 6)
                        patched_addrs.append(hex(jmp_ins_addr))
                    elif suc[1].addr in self.control_flow and suc[0].addr not in self.control_flow: 
                    # 若第二个后继可达，第一个不可达
                        write_nops(data, jmp_ins_addr - base_address, 6)
                        write_jmp(data, jmp_ins_addr - base_address, suc[1].addr - jmp_ins_addr - 6)
                        patched_addrs.append(hex(jmp_ins_addr))
        print(f'Patched {len(patched_addrs)} jump instructions: {patched_addrs}')


    def patch_binary(self):
        with open(self.filename, 'rb') as inp:  # 读取目标文件
            data = bytearray(inp.read())  # 字节数组
        self.patch_unreachable_blocks(data)  # 修改不可达块为nop
        self.patch_jump(data)  # 修改jump指令
        # 将去混淆的结果保存到另一个文件
        name, suffix = split_suffix(self.filename)
        outpath = name + '_recovered' + suffix
        with open(outpath,'wb') as out:
            out.write(data)
        print(f'Recovered file is saved to: {outpath}')

    def debcf(self):
        self.load_target_blocks()  # 获取目标函数所有基本块
        self.hook()  # hook掉目标函数中调用的其他函数
        self.symbolic_execute()  # 符号执行，找到所有可达块
        self.patch_binary()  # 得到去混淆的结果文件

if __name__ == '__main__':
    parser = argparse.ArgumentParser()   # 命令行选项、参数和子命令解析器。
    # 给一个 ArgumentParser 添加参数信息
    parser.add_argument('-f', '--file', help='The path of binary file to deobfuscate')
    parser.add_argument('-s', '--start', help='Start address of target function')
    parser.add_argument('-e', '--end', help='End address of target function')
    args = parser.parse_args()   # 通过 parse_args() 方法解析参数
    if args.file == None or args.start == None or args.end == None:
        parser.print_help()
        exit(0)
    filename = args.file
    start_address = int(args.start, 16)
    end_address = int(args.end, 16)

    deboguser = Deboguser(filename=filename,start_address=start_address,end_address=end_address)
    deboguser.debcf()