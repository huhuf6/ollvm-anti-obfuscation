#!/usr/bin/env python3

import sys,os

sys.path.append("..")

import argparse
import angr
import pyvex
import claripy
import struct
from collections import defaultdict
from util import *
import am_graph
import pdb

import logging

logging.getLogger('angr.state_plugins.symbolic_memory').setLevel(logging.ERROR)
regstr='r0'

addrinqueue = None
queue = None
regs_info = None
flow = None
retaddr = None
main_dispatcher_node = None
special_relevant_nodes = {}


def get_regs(state,regs_info):
    #regs_info['r0'] = state.solver.eval(state.regs.r0)
    #regs_info['r1'] = state.solver.eval(state.regs.r1)
    regs_info['r2'] = state.solver.eval(state.regs.r2)
    regs_info['r3'] = state.solver.eval(state.regs.r3)
    regs_info['r4'] = state.solver.eval(state.regs.r4)
    regs_info['r5'] = state.solver.eval(state.regs.r5)
    regs_info['r6'] = state.solver.eval(state.regs.r6)
    regs_info['r7'] = state.solver.eval(state.regs.r7)
    regs_info['r8'] = state.solver.eval(state.regs.r8)
    regs_info['r9'] = state.solver.eval(state.regs.r9)
    regs_info['r10'] = state.solver.eval(state.regs.r10)
    regs_info['r11'] = state.solver.eval(state.regs.r11)
    regs_info['r12'] = state.solver.eval(state.regs.r12)
    regs_info['sp'] = state.solver.eval(state.regs.sp)
    regs_info['lr'] = state.solver.eval(state.regs.lr)
    #regs_info['pc'] = state.solver.eval(state.regs.pc)
    regs_info['stack_data'] = state.memory.load(state.regs.sp, 20)
    print(regs_info['stack_data'])
    return regs_info




def get_relevant_nodes(supergraph,main_dispatcher_node,project):
    global pre_dispatcher_node, prologue_node, retn_node,regstr
    relevants = []
    def find_other_releventnodes(node,isSecondLevel):
        prenodes = list(supergraph.predecessors(node))
        for prenode in prenodes:
            if len(list(supergraph.successors(prenode)))==1:
                relevants.append(prenode)
                # insn judge
                if isSecondLevel and not(is_has_disasmes_in_node(node, [['mov', regstr]],project) or is_has_disasmes_in_node(node, [['ldr', regstr]],project)):
                    special_relevant_nodes[prenode.addr]=node.addr
                find_other_releventnodes(prenode,False)

    nodes = list(supergraph.predecessors(main_dispatcher_node))
    print(nodes)
    for node in nodes:
        insns = project.factory.block(node.addr).capstone.insns
        if node in relevants:
            continue
        elif len(insns)==4 and insns[0].insn.mnemonic.startswith('mov') and insns[1].insn.mnemonic.startswith('mov') and insns[2].insn.mnemonic.startswith('cmp') and is_jmp_code(insns[3].insn.mnemonic):
            continue
        elif len(insns)==1 and is_jmp_code(insns[0].insn.mnemonic):
            continue
        elif len(insns)==2 and insns[0].insn.mnemonic.startswith('cmp') and is_jmp_code(insns[1].insn.mnemonic):
            continue
        elif len(insns)==3 and insns[0].insn.mnemonic.startswith('cmp') and insns[1].insn.mnemonic.startswith('mov') and is_jmp_code(insns[2].insn.mnemonic):
            continue
        elif len(insns)==5 and (is_has_disasmes_in_node(node,[['mov',''],['mov',''],   ['cmp',''],['ldr',regstr]],project) or
            is_has_disasmes_in_node(node,[['mov',''],['mov',''],['cmp',''],['mov',regstr]],project) )and is_jmp_code(insns[4].insn.mnemonic):
            continue
        elif is_has_disasmes_in_node(node,[['add','sp']],project) and is_has_disasmes_in_node(node,[['nop','']],project):
            continue

        relevants.append(node)
        find_other_releventnodes(node,True)
    return relevants

def is_startwith(str1,str2):
    if str2=='':
        return True
    return str1.startswith(str2)

def is_jmp_code(str):
    if not str.startswith('b'):
        return False
    if str.startswith('bl'):
        if str.startswith('ble') and not str.startswith('bleq'):
            return True
        else: return False
    return True

def is_call_code(str):
    if not str.startswith('bl'):
        return False
    if str.startswith('ble') and not str.startswith('bleq'):
        return False
    return True

def is_has_disasmes_in_insns(insns,disinfolist):
    size = len(disinfolist)
    for i in range(len(insns) - (size-1)):
        is_has = True
        for j in range(size):
            insn=insns[i+j].insn
            disinfo=disinfolist[j]
            if not (is_startwith(insn.mnemonic,disinfo[0]) and is_startwith(insn.op_str,disinfo[1])):
                is_has=False
                break
        if is_has: return True
    return False

def is_has_disasmes_in_node(node,disinfolist,project):
    insns=project.factory.block(node.addr,node.size).capstone.insns
    return is_has_disasmes_in_insns(insns,disinfolist)

def get_relevant_nop_nodes(supergraph, relevant_block_addrs,prologue_node, retn_node):
    # relevant_nodes = list(supergraph.predecessors(pre_dispatcher_node))
    nop_nodes = []
    for node in supergraph.nodes():
        if node.addr in  relevant_block_addrs:
            continue
        nop_nodes.append(node)
    print(i.addr for i in nop_nodes)
    return  nop_nodes


def get_node(supergraph,addr):
    for node in supergraph.nodes():
        if node.addr ==addr:
            return node
# logging.getLogger('angr.sim_manager').setLevel(logging.DEBUG)




def symbolic_execution_arm(project, relevant_block_addrs,start_addr, state, bl_addrs=None, branch_addr=None):

    global main_dispatcher_node,retaddr,flow,regs_info,queue,addrinqueue

    def handle_bl(state):
        pass

    def handle_branch(state):
        pass

    def init_regs(state, regs_info):
        if len(regs_info) == 0:
            print("no reg_info")
            return
        for regstr, regvalue in regs_info.items():
            if regstr == 'r0':
                state.regs.r0 = claripy.BVV(regvalue, 32)
            elif regstr == 'r1':
                state.regs.r1 = claripy.BVV(regvalue, 32)
            elif regstr == 'r2':
                state.regs.r2 = claripy.BVV(regvalue, 32)
            elif regstr == 'r3':
                state.regs.r3 = claripy.BVV(regvalue, 32)
            elif regstr == 'r4':
                state.regs.r4 = claripy.BVV(regvalue, 32)
            elif regstr == 'r5':
                state.regs.r5 = claripy.BVV(regvalue, 32)
            elif regstr == 'r6':
                state.regs.r6 = claripy.BVV(regvalue, 32)
            elif regstr == 'r7':
                state.regs.r7 = claripy.BVV(regvalue, 32)
            elif regstr == 'r8':
                state.regs.r8 = claripy.BVV(regvalue, 32)
            elif regstr == 'r9':
                state.regs.r9 = claripy.BVV(regvalue, 32)
            elif regstr == 'r10':
                state.regs.r10 = claripy.BVV(regvalue, 32)
            elif regstr == 'r11':
                state.regs.r11 = claripy.BVV(regvalue, 32)
            elif regstr == 'r12':
                state.regs.r12 = claripy.BVV(regvalue, 32)
            elif regstr == 'sp':
                state.regs.sp = claripy.BVV(regvalue, 32)
            elif regstr == 'lr':
                state.regs.lr = claripy.BVV(regvalue, 32)
            elif regstr == 'pc':
                state.regs.pc = claripy.BVV(regvalue, 32)
        state.memory.store(state.regs.sp,regs_info['stack_data'])

    if bl_addrs!=None:
        for addr in bl_addrs:
            project.hook(addr[0], handle_bl, addr[1])
    if branch_addr!=None:
        project.hook(branch_addr[0],handle_branch,branch_addr[1],replace=True)



    state = project.factory.blank_state(addr=start_addr, remove_options={angr.sim_options.LAZY_SOLVES},
                                        add_option={angr.options.SYMBOLIC_WRITE_ADDRESSES,})


    sm = project.factory.simulation_manager(state)
    init_regs(state, regs_info)

    loopTime=0
    maxLoopTime=1
    skip_addr=None
    if start_addr in special_relevant_nodes:
        skip_addr=special_relevant_nodes[start_addr]
        maxLoopTime+=1

    sm.step()
    while len(sm.active) > 0:
        for active_state in sm.active:

                #if active_state.addr in relevant_block_addrs and active_state.addr != skip_addr:
            if active_state.addr in relevant_block_addrs :
                print('%#x' % active_state.addr)
                return active_state.addr
            print('%#x'%active_state.addr)
        sm.step()



def symbolic_execution(project, relevant_block_addrs, start_addr, hook_addrs=None, modify_value=None, inspect=False):
    def retn_procedure(state):
        ip = state.solver.eval(state.regs.ip)
        project.unhook(ip)
        return

    def statement_inspect(state):
        expressions = list(
            state.scratch.irsb.statements[state.inspect.statement].expressions)
        if len(expressions) != 0 and isinstance(expressions[0], pyvex.expr.ITE):
            state.scratch.temps[expressions[0].cond.tmp] = modify_value
            state.inspect._breakpoints['statement'] = []

    if hook_addrs is not None:
        skip_length = 4
        if project.arch.name in ARCH_X86:
            skip_length = 5

        for hook_addr in hook_addrs:
            project.hook(hook_addr, retn_procedure, length=skip_length)

    state = project.factory.blank_state(addr=start_addr, remove_options={
        angr.sim_options.LAZY_SOLVES})
    if inspect:
        state.inspect.b(
            'statement', when=angr.state_plugins.inspect.BP_BEFORE, action=statement_inspect)
    sm = project.factory.simulation_manager(state)
    sm.step()
    while len(sm.active) > 0:
        for active_state in sm.active:
            if active_state.addr in relevant_block_addrs:
                return active_state.addr
        sm.step()

    return None


def main():
    global main_dispatcher_node,retaddr,flow,regs_info
    filename = "libNativeExample.so"
    path = os.path.join(os.getcwd(), filename)
    filename=path
    start = 0x400FD9
    length = 0x3A0
    with open(filename, 'rb') as origin:
        # Attention: can't transform to str by calling decode() directly. so use bytearray instead.
        origin_data = bytearray(origin.read())
        origin_data_len = len(origin_data)
    project = angr.Project(filename, load_options={'auto_load_libs': False})
    # do normalize to avoid overlapping blocks, disable force_complete_scan to avoid possible "wrong" blocks
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    print(cfg.graph)

    target_function = cfg.functions.get(start)
    # A super transition graph is a graph that looks like IDA Pro's CFG CFGFast(normalize=True, force_complete_scan=False)
    for node in target_function.transition_graph:
        print("%#x"%node.addr)

    supergraph = am_graph.to_supergraph(target_function.transition_graph)

    base_addr = project.loader.main_object.mapped_base >> 12 << 12

    # get prologue_node and retn_node
    prologue_node = None
    for node in supergraph.nodes():
        if supergraph.in_degree(node) == 0:
            prologue_node = node
        if supergraph.out_degree(node) == 0 and len(node.out_branches) == 0:
            retn_node = node

    if prologue_node is None or prologue_node.addr != start:
        print("Something must be wrong...")
        sys.exit(-1)
    main_dispatcher_node = get_node(supergraph, 0x4012b3)
    print(main_dispatcher_node)

    relevant_nodes = get_relevant_nodes(supergraph,main_dispatcher_node,project)



    retaddr = retn_node.addr
    print('*******************relevant blocks************************')
    print('prologue: %#x' % start)
    print('main_dispatcher: %#x' % main_dispatcher_node.addr)
    print('retn: %#x' % retn_node.addr)
    relevant_block_addrs = [node.addr for node in relevant_nodes]
    print('relevant_blocks:', [hex(addr) for addr in relevant_block_addrs])
    special_relevant_nodes_addrs = [special_relevant_nodes[node] for node in special_relevant_nodes]
    print('special relevant_blocks:', [hex(addr) for addr in special_relevant_nodes_addrs])


    print('*******************symbolic execution*********************')
    relevants = relevant_nodes
    relevants_without_retn = list(relevants)
    relevants.append(retn_node)
    relevant_block_addrs.extend([retn_node.addr])

    nop_nodes = get_relevant_nop_nodes(
        supergraph, relevant_block_addrs,prologue_node, retn_node)

    regs_info = defaultdict(list)
    flow = defaultdict(list)
    patch_instrs = {}


    state = project.factory.entry_state(addr=prologue_node.addr, remove_options={angr.sim_options.LAZY_SOLVES},
                                        add_option={angr.options.SYMBOLIC_WRITE_ADDRESSES})


    sm = project.factory.simulation_manager(state)
    sm.step()
    regs_info = get_regs(sm.active[0], regs_info)


    for relevant in relevants_without_retn:
        block = project.factory.block(relevant.addr, relevant.size)
        insns = block.capstone.insns
        it_patch_addr = []
        it_ins_count = 0
        for ins in insns:
            if relevant.addr == start:
                continue
            if project.arch.name in ARCH_ARM:
                if ins.insn.mnemonic.startswith('it'):
                    it_ins_count+=1
                    it_patch_addr.append(ins.address)
        if it_ins_count >= 2:
            i = len(it_patch_addr) - 1
            while i != len(it_patch_addr) - 3:
                fill_nop_thumb(origin_data, it_patch_addr[i] - base_addr , 2, project.arch)
                i = i - 1

    mid_file = filename + '_mid'
    recovery_mid = open(mid_file, 'wb')
    recovery_mid.write(origin_data)
    recovery_mid.close()

    filename = mid_file
    path = os.path.join(os.getcwd(), filename)
    filename=path
    start = 0X400fd9
    length = 0x3A0
    with open(filename, 'rb') as origin:
        # Attention: can't transform to str by calling decode() directly. so use bytearray instead.
        origin_data = bytearray(origin.read())
        origin_data_len = len(origin_data)
    project = angr.Project(filename, load_options={'auto_load_libs': False})
    # do normalize to avoid overlapping blocks, disable force_complete_scan to avoid possible "wrong" blocks
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    print(cfg.graph)

    target_function = cfg.functions.get(start)
    # A super transition graph is a graph that looks like IDA Pro's CFG CFGFast(normalize=True, force_complete_scan=False)
    for node in target_function.transition_graph:
        print("%#x"%node.addr)

    supergraph = am_graph.to_supergraph(target_function.transition_graph)

    base_addr = project.loader.main_object.mapped_base >> 12 << 12

    # get prologue_node and retn_node
    prologue_node = None
    for node in supergraph.nodes():
        if supergraph.in_degree(node) == 0:
            prologue_node = node
        if supergraph.out_degree(node) == 0 and len(node.out_branches) == 0:
            retn_node = node

    if prologue_node is None or prologue_node.addr != start:
        print("Something must be wrong...")
        sys.exit(-1)
    main_dispatcher_node = get_node(supergraph, 0x4012b3)
    print(main_dispatcher_node)

    relevant_nodes = get_relevant_nodes(supergraph,main_dispatcher_node,project)



    retaddr = retn_node.addr
    relevant_block_addrs = [node.addr for node in relevant_nodes]
    print('relevant_blocks:', [hex(addr) for addr in relevant_block_addrs])
    special_relevant_nodes_addrs = [special_relevant_nodes[node] for node in special_relevant_nodes]
    relevants = relevant_nodes
    relevants_without_retn = list(relevants)
    relevants.append(retn_node)
    relevant_block_addrs.extend([retn_node.addr])
    nop_nodes = get_relevant_nop_nodes(
        supergraph, relevant_block_addrs,prologue_node, retn_node)

    regs_info = defaultdict(list)
    flow = defaultdict(list)
    patch_instrs = {}


    state = project.factory.entry_state(addr=prologue_node.addr, remove_options={angr.sim_options.LAZY_SOLVES},
                                        add_option={angr.options.SYMBOLIC_WRITE_ADDRESSES})


    sm = project.factory.simulation_manager(state)
    sm.step()
    regs_info = get_regs(sm.active[0], regs_info)

    for relevant in relevants_without_retn:
        print('-------------------dse %#x---------------------' % relevant.addr)

        block = project.factory.block(relevant.addr, relevant.size)
        has_branches = False
        hook_addrs = set([])
        insns = block.capstone.insns
        bl_addr = []
        it_addr = []
        count=0
        for ins in insns:
            if project.arch.name in ARCH_ARM:
                if relevant.addr == start:
                    continue
                if ins.insn.mnemonic.startswith('itt') :
                    if relevant not in patch_instrs:
                        patch_instrs[relevant] = ins
                        j = ins.mnemonic.count('t')
                        if(count+j+1>=len(insns)):
                            it_addr.append((ins.address, insns[count + j  ].insn.address - ins.address+2))
                            print(insns[count + j])
                            print('***spec***')
                        else:
                            it_addr.append((ins.address, insns[count + j + 1].insn.address - ins.address))
                            print(insns[count + j + 1])

                        it_addr.append((ins.address, insns[count + 1].insn.address - ins.address))
                        print(insns[count + 1])
                        print(insns[count + 2])
                        has_branches = True

                elif ins.insn.mnemonic in {'bl', 'blx'}:
                    bl_addr.append((ins.address,ins.size))
            count = count+1


        if has_branches:
            flow[relevant].append(symbolic_execution_arm(project,relevant_block_addrs,relevant.addr,state,bl_addr,it_addr[0] ))
            print("***second***")
            flow[relevant].append(symbolic_execution_arm(project,relevant_block_addrs,relevant.addr,state,bl_addr,it_addr[1] ))
        else:
            flow[relevant].append(symbolic_execution_arm(project,relevant_block_addrs,relevant.addr,state,bl_addr))

    print('************************flow******************************')
    for k, v in flow.items():
        print('%#x: ' % k.addr, [hex(child) for child in v])

    print('%#x: ' % retn_node.addr, [])

    print('************************patch*****************************')

    filename = "libNativeExample.so"
    recovery_file = filename + '_recovered'
    recovery = open(recovery_file, 'wb')

    # patch irrelevant blocks
    print("***nop_nodes***")
    for nop_node in nop_nodes:
        print("%#x"%nop_node.addr)
        fill_nop_thumb(origin_data, nop_node.addr - base_addr,
                 nop_node.size, project.arch)

    # remove unnecessary control flows
    for parent, childs in flow.items():
        if len(childs) == 1:
            parent_block = project.factory.block(parent.addr, size=parent.size)
            last_instr = parent_block.capstone.insns[-1]
            file_offset = last_instr.address - base_addr
            # patch the last instruction to jmp
            if project.arch.name in ARCH_X86:
                fill_nop(origin_data, file_offset,
                         last_instr.size, project.arch)
                patch_value = ins_j_jmp_hex_x86(last_instr.address, childs[0], 'jmp')
            elif project.arch.name in ARCH_ARM:
                if last_instr.insn.mnemonic.startswith('b'):
                    patch_value = ins_b_jmp_hex_arm_thumb(last_instr.address, childs[0], 'b')
                else:
                    patch_value = ins_b_jmp_hex_arm_thumb(last_instr.address+last_instr.size, childs[0], 'b')
                if project.arch.memory_endness == "Iend_BE":
                    patch_value = patch_value[::-1]
            elif project.arch.name in ARCH_ARM64:
                # FIXME: For aarch64/arm64, the last instruction of prologue seems useful in some cases, so patch the next instruction instead.
                if parent.addr == start:
                    file_offset += 4
                    patch_value = ins_b_jmp_hex_arm64(last_instr.address + 4, childs[0], 'b')
                else:
                    patch_value = ins_b_jmp_hex_arm64(last_instr.address, childs[0], 'b')
                if project.arch.memory_endness == "Iend_BE":
                    patch_value = patch_value[::-1]
            if project.arch.name in ARCH_ARM:
                file_offset-=1
            if last_instr.insn.mnemonic.startswith('b'):
                patch_instruction(origin_data, file_offset, patch_value)
            elif (last_instr.address+last_instr.size) not in relevant_block_addrs:
                print("no b ins size")
                print(last_instr.size)
                patch_instruction(origin_data, file_offset+last_instr.size, patch_value)
        else:
            parent_block = project.factory.block(parent.addr, size=parent.size)
            instr = patch_instrs[parent]
            file_offset = instr.address - base_addr
            if project.arch.name in ARCH_ARM:
                file_offset-=1
            # patch instructions starting from `cmovx` to the end of block
            #fill_nop_thumb(origin_data, file_offset, parent.addr +
            #         parent.size - base_addr - file_offset, project.arch)
            if project.arch.name in ARCH_X86:
                # patch the cmovx instruction to jx instruction
                patch_value = ins_j_jmp_hex_x86(instr.address, childs[0], instr.mnemonic[len('cmov'):])
                patch_instruction(origin_data, file_offset, patch_value)

                file_offset += 6
                # patch the next instruction to jmp instrcution
                patch_value = ins_j_jmp_hex_x86(instr.address + 6, childs[1], 'jmp')
                patch_instruction(origin_data, file_offset, patch_value)
            elif project.arch.name in ARCH_ARM:
                # patch the movx instruction to bx instruction
                print("*****************")

                print('%#x'%instr.address)
                bx_cond = 'b' + instr.op_str
                print(bx_cond)
                if last_instr.insn.mnemonic.startswith('b'):
                    fill_nop_thumb(origin_data, instr.address - base_addr + 4,
                                   8, project.arch)
                else:
                    fill_nop_thumb(origin_data, instr.address - base_addr + 4,
                                   6, project.arch)
                if abs(childs[1] - instr.address) > 255:
                    jump_board_flag = 0
                    print("need jump board")
                    for nop_node in nop_nodes :
                        if (abs(nop_node.addr-instr.address) <255 ) and (abs(nop_node.addr - childs[1]) <2047):
                            nop_offset = nop_node.addr - base_addr-1
                            nop_patch_value = ins_b_jmp_hex_arm_thumb(nop_node.addr+4, childs[1], 'b')
                            print(nop_patch_value)
                            patch_instruction(origin_data, nop_offset+4, nop_patch_value)
                            patch_value = ins_b_jmp_hex_arm_thumb(instr.address, nop_node.addr+2, bx_cond)
                            nop_nodes.remove(nop_node)
                            jump_board_flag = 1
                            print("%#x"%nop_node.addr)
                            print("find jump board")
                            break
                    if(jump_board_flag == 0):
                        nop_offset = instr.address - base_addr - 1
                        nop_patch_value = ins_b_jmp_hex_arm_thumb(instr.address + 4, childs[1], 'b')
                        print(nop_patch_value)
                        patch_instruction(origin_data, nop_offset + 4, nop_patch_value)
                        patch_value = ins_b_jmp_hex_arm_thumb(instr.address, instr.address + 4, bx_cond)
                        print("%#x" % nop_node.addr)
                        print("find jump board")
                else:
                    patch_value = ins_b_jmp_hex_arm_thumb(instr.address, childs[1], bx_cond)
                    print('no jump board')
                if project.arch.memory_endness == 'Iend_BE':
                    patch_value = patch_value[::-1]
                patch_instruction(origin_data, file_offset, patch_value)
                print(patch_value)
                file_offset += 2
                # patch the next instruction to b instrcution
                patch_value = ins_b_jmp_hex_arm_thumb(instr.address + 2, childs[0], 'b')
                if project.arch.memory_endness == 'Iend_BE':
                    patch_value = patch_value[::-1]
                patch_instruction(origin_data, file_offset, patch_value)
                last_instr = parent_block.capstone.insns[-1]


            elif project.arch.name in ARCH_ARM64:
                # patch the cset.xx instruction to bx instruction
                bx_cond = instr.op_str.split(',')[-1].strip()
                print("*****************")
                print(instr.op_str)
                patch_value = ins_b_jmp_hex_arm64(instr.address, childs[1], bx_cond)
                if project.arch.memory_endness == 'Iend_BE':
                    patch_value = patch_value[::-1]
                patch_instruction(origin_data, file_offset, patch_value)

                file_offset += 4
                # patch the next instruction to b instruction
                patch_value = ins_b_jmp_hex_arm64(instr.address + 4, childs[0], 'b')
                if project.arch.memory_endness == 'Iend_BE':
                    patch_value = patch_value[::-1]
                patch_instruction(origin_data, file_offset, patch_value)

    assert len(origin_data) == origin_data_len, "Error: size of data changed!!!"
    recovery.write(origin_data)
    recovery.close()
    print('Successful! The recovered file: %s' % recovery_file)


if __name__ == '__main__':
    main()