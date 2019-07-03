#!/usr/bin/python3
import subprocess as sp
import argparse
import os
import sys
import csv
import tempfile


def rm_empty_str(objs):
    return {i for i in objs if i != ''}

class LibvirtQemu:
    def __init__(self, src, mode):
        if mode not in {'qmp', 'ga'}:
            raise TypeError('mode should be "qmp" or "ga"')
        self.src = src
        self.mode = mode
        if mode == 'qmp':
            self.makecmd = 'qemuMonitorJSONMakeCommand'
        if mode == 'ga':
            self.makecmd = 'qemuAgentMakeCommand'
        self.tmpdir = tempfile.mkdtemp()
        self.qemu_cscope_source = os.path.join(self.src, 'src/qemu')
        self.qemu_cscope = self.gen_qemu_cscope('qemu')
        self.libvirt_apis = self.get_libvirt_apis()
        self.qemu_apis = {i.replace("vir", "qemu", 1)
                          for i in self.libvirt_apis}
        self.mon_funcs = self.get_mon_funcs()

    def get_libvirt_apis(self):
        cmd = 'grep "virDomain[a-zA-Z0-9]*" %s -o' % os.path.join(
            self.src, 'src/libvirt_public.syms')
        return rm_empty_str(sp.check_output(cmd, shell=True, text=True).split('\n'))

    def gen_qemu_cscope(self, name):
        cscope = os.path.join(self.tmpdir, '%s.out' %name)
        cmd = 'cscope -b -f %s -s %s -R' % (cscope, self.qemu_cscope_source)
        try:
            sp.check_output(cmd, shell=True)
        except sp.CalledProcessError as e:
            sys.exit("%s cscope generate failed: %s\nreturn: %d" %
                     (name, cmd, e.returncode))
        return cscope

    def get_mon_funcs(self):
        cmd = "cscope -d -L3 %s -s %s -f %s|grep -v '^[a-zA-Z_0-9]*\.h'|grep -v ATTRIBUTE_ |awk '{print $2}'" % (
            self.makecmd, self.qemu_cscope_source, self.qemu_cscope)
        return rm_empty_str(sp.check_output(cmd, shell=True, text=True).split('\n'))

    def get_qemu_exec(self, mon_func):
        if self.mode == 'qmp':
            mon_file = 'qemu_monitor_json.c'
        if self.mode == 'ga':
            mon_file = 'qemu_agent.c'
        qemu_mon_src = os.path.join(self.src, 'src/qemu/%s' %mon_file)
        cmd = """awk '/%s/,/^}/' %s|awk '/%s/,/)/'|grep '"[a-zA-Z:_-]*"' -o |tr '\n' ','""" % (
            mon_func, qemu_mon_src, self.makecmd)
        return sp.check_output(cmd, shell=True, text=True)

    def get_callers(self, fn):
        cmd = "cscope -d -L3 %s -f %s -s %s|grep -v '^[a-zA-Z_0-9]*\.h' | grep -v ATTRIBUTE_ | awk '{print $2}'" % (
            fn, self.qemu_cscope, self.qemu_cscope_source)
        return rm_empty_str(sp.check_output(cmd, shell=True, text=True).split('\n'))

    def get_top_callers(self, fn, cscope):
        stack = []
        top_callers = set()
        accessed = set()
        func = fn
        stack.append(func)
        while stack != []:
            func = stack.pop()
            if func not in accessed:
                accessed.add(func)
                callers = self.get_callers(func)
                if func in callers or callers == set():
                    top_callers.add(func)
                for caller in callers:
                    stack.append(caller)
        return top_callers

    def writecsv(self, csv_path):
        with open(csv_path, 'w') as csvfile:
            header = ["Monitor Wrapper", "QMP", "API callers", "Callers not in APIs"]
            writer = csv.DictWriter(csvfile, fieldnames=header, delimiter='|')
            writer.writeheader()

            for mon in self.mon_funcs:
                qemu_exec = self.get_qemu_exec(mon)
                top_callers = self.get_top_callers(mon, self.qemu_cscope)
                callers_api = "\n".join([j.replace('qemu', 'vir', 1) for j in {i for i in top_callers if i in self.qemu_apis}])
                callers_not_api = "\n".join([i for i in top_callers if i not in self.qemu_apis])
                writer.writerow({
                    header[0]: mon,
                    header[1]: qemu_exec,
                    header[2]: callers_api,
                    header[3]: callers_not_api})

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--source', help="The libvirt source directory", required=True)
    parser.add_argument('-m', '--mode', help="The mode of API mappings.'qmp': The qemu qmp to libvirt API mappings; 'ga': The qemu guest agent command to libvirt API mappings", required=True)
    parser.add_argument('-o', '--output', help="The csv output file", default='output.csv')
    args = parser.parse_args()

    LibvirtQemu(args.source, args.mode).writecsv(args.output)
