#!/usr/bin/env python2
# -*- coding: utf-8 -*-


import idaapi
import idc
import idautils
import sys
import struct
from elftools.elf.elffile import ELFFile
from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from keystone import *
from keystone import Ks, KS_MODE_THUMB, KS_ARCH_ARM, KS_MODE_ARM

sys.path.append('/usr/local/lib/python2.7/site-packages/')
IMAGE_BASE = idaapi.get_imagebase()#获取虚拟地址起始基址
DEBUG = True

#这段代码添加了一个HOOK（向Unicorn引擎中），我们定义的函数会在执行每一条命令之前被执行。参数含义如下：
#1 Uc实例 2 指令的地址 3 指令的长度 4 用户定义数据（通过hook_add()函数传递）

def hook_code(uc, address, size, user_data):
    instruction = uc.mem_read(address, size)
    if instruction == b'\xc3':#0xc3 is just the return instruction
        uc.emu_stop()

    if address == 0:
        uc.emu_stop()

    if address != 0 and address != IMAGE_BASE:
        idc.set_color(address, idc.CIC_ITEM, 0xFFB6C1)

    if DEBUG:
        _code = idc.GetDisasm(address)
        #print("0x%016x \t%s" % (address, _code))


class Simulator(object):
    def __init__(self):
        self.segments = []
        self.mem_map = []

        self.ph_flag = None
        self.ph_id = None

        self.arch = None
        self.mode = None

        self.sp = None

        self.stack_base = 0
        self.stack_length = 1024 * 1024 * 2

        self.get_segments()
        self.get_arch()
        self.get_unicorn_mem_pages()

#获取ida调试程序中的段
    def get_segments(self):
        if len(self.segments) == 0:
            for seg in idautils.Segments():#查找段
                name = idc.SegName(seg)
                start = idc.SegStart(seg)
                end = idc.SegEnd(seg)
                d = idc.GetManyBytes(start, end - start)#获取数据
                d = [ord(item) for item in list(d)]#转化为ascii码
                seg_data = {"name": name, "start": start, "end": end, "data": d}
                self.segments.append(seg_data)#添加进段中
        return self.segments
#获取文件架构信息
    def get_arch(self):
        self.ph_id = idaapi.ph.id
        self.ph_flag = idaapi.ph.flag

        if self.ph_id == idaapi.PLFM_386 and self.ph_flag & idaapi.PR_USE64:
            self.arch = UC_ARCH_X86
            self.mode = UC_MODE_64
            self.sp = UC_X86_REG_RSP
        elif self.ph_id == idaapi.PLFM_386 and self.ph_flag & idaapi.PR_USE32:
            self.arch = UC_ARCH_X86
            self.mode = UC_MODE_32
            self.sp = UC_X86_REG_RSP
        elif self.ph_id == idaapi.PLFM_ARM and self.ph_flag & idaapi.PR_USE32:
            self.arch = UC_ARCH_ARM
            self.mode = UC_MODE_ARM
            self.sp = UC_ARM_REG_SP
        elif self.ph_id == idaapi.PLFM_ARM and self.ph_flag & idaapi.PR_USE64:
            self.arch = UC_ARCH_ARM64
            self.mode = UC_MODE_ARM
            self.sp = UC_ARM64_REG_SP


#判断是否是手机arm
    def emu_start(self, func_start, func_end):
        if self.arch == UC_ARCH_ARM:
            if self.is_thumb_ea(func_start):
                print("thumb mode")
                self.mode = UC_MODE_THUMB
        mu = Uc(self.arch, self.mode)
        #给段分配内存
        for item in self.mem_map:
            Simulator.map_memory(mu, item['start'], item['length'])

        # 给栈分配内存
        Simulator.map_memory(mu, self.stack_base, self.stack_length)

        # 写入数据
        for item in self.segments:
            Simulator.write_memory(mu, item['start'], item['data'])

        # 配置寄存器
        mu.reg_write(self.sp, self.stack_base + 1024 * 1024)

        mu.hook_add(UC_HOOK_CODE, hook_code)

        try:
            # 开始执行
            mu.emu_start(func_start, func_end)
        except Exception as e:
            print("Err: %s. Execution function failed.(The function address is 0x%x)" % (e, func_start))

        # 读取数据
        for item in self.segments:
            _data = Simulator.read_memory(mu, item['start'], item['end'])#读取每段中的数据
            self.replace_data(item['start'], _data)#数据替换

        print("Patch data")
        filename = "H:/ollvm str/test.so"
        fd = open(filename, 'r+b')
        elf = ELFFile(fd)
        data_section_header = elf.get_section_by_name('.data').header
        new_data = Simulator.read_memory(mu,data_section_header.sh_addr, data_section_header.sh_size+data_section_header.sh_addr)

        print("Patch func_div with ret")

        fd.seek(data_section_header.sh_offset)
        fd.write(new_data)
        print("Patch data succeed")

        ks_86_64 = Ks(KS_ARCH_X86, KS_MODE_64)
        fd.seek(start & 0xFFFFFFFE)
        a = ks_86_64.asm(b"ret")[0]
        for _ in a:
            fd.write(struct.pack("B", _))#将二进制指令添加到原文件中

        fd.close()
        print("done!")

        # unmap memory释放内存
        for item in self.mem_map:
            Simulator.unmap_memory(mu, item['start'], item['length'])

        Simulator.unmap_memory(mu, self.stack_base, self.stack_length)

    def replace_data(self, start, data):
        for i in range(len(self.segments)):
            if self.segments[i]['start'] == start:
                self.segments[i]['data'] = data

    @staticmethod
    def write_memory(mu, start, data):
        if isinstance(data, list):
            data = bytearray(data)
        mu.mem_write(start, bytes(data))

    @staticmethod
    def read_memory(mu, start, end):
        _length = end - start
        _data = mu.mem_read(start, _length)
        return bytearray(_data)

    @staticmethod
    def map_memory(mu, start, _length):
        mu.mem_map(start, _length)
        print("map memory: offset 0x%x, size: 0x%x" % (start, _length))

    @staticmethod
    def unmap_memory(mu, start, _length):
        mu.mem_unmap(start, _length)
        print("unmap memory: offset 0x%x, size: 0x%x" % (start, _length))

    @staticmethod
    def get_base_and_len(base, length):
        _base = base - (base % (1024 * 1024))
        _length = (length / (1024 * 1024) + 1) * 1024 * 1024
        return _base, _length

    def get_unicorn_mem_pages(self):
        if len(self.segments) == 0:
            return None

        if len(self.mem_map) == 0:
            seg = None
            pages = []
            for item in self.segments:
                if not seg:
                    seg = {'start': item['start'], 'end': item['end']}
                else:
                    if item['start'] - seg['end'] > (1024 * 1024 * 2):
                        pages.append(seg)
                        seg = {'start': item['start'], 'end': item['end']}
                    else:
                        seg['end'] = item['end']
            pages.append(seg)

            for item in pages:
                start, length = Simulator.get_base_and_len(item['start'], item['end'] - item['start'])
                self.mem_map.append({"start": start, "length": length})
                print("start:%d  length:%d",start,length)

            for item in self.mem_map:
                if self.stack_base < item['start'] + item['length']:
                    self.stack_base = item['start'] + item['length']
                    print(self.stack_base)
        return self.mem_map




#初始化模拟器
sim = Simulator()
#遍历函数
for func in idautils.Functions():
    func_name = idc.GetFunctionName(func)
    func_data = idaapi.get_func(func)
    start = func_data.start_ea  #获取函数的起始地址
    end = func_data.end_ea      ##获取函数的结束地址
    print(func_name, hex(start), hex(end))
    #判断是否是解密函数，如果是，则执行解密函数
    if "datadiv_decode" in func_name :
        print("found div func")
        sim.emu_start(start, end)

for seg in sim.segments:#segments段中存放了so文件的段信息
    if "data" in seg['name']:
        # 把data段全部undefined
        print("MakeUnknown %s" % seg['name'])
        idc.MakeUnknown(seg['start'], seg['end'] - seg['start'], idaapi.DELIT_DELNAMES)
        # 调用ida重新解析data段
        print("analyze area: 0x%x - 0x%x" % (seg['start'], seg['end']))
        idaapi.analyze_area(seg['start'], seg['end'])
        # idaapi.clear_strlist()
        # idaapi.build_strlist()

