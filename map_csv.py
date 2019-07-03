#!/usr/bin/python3
import subprocess as sp
import argparse
import os
import sys
import csv
import tempfile


class LibvirtQemu:
    def __init__(self, src, makecmd):
        self.src = src
        self.makecmd = makecmd
        self.tmpdir = tempfile.mkdtemp()
        self.libvirt_apis = self.get_libvirt_apis()
        self.qemu_apis = {i.replace("vir", "qemu", 1)
                          for i in self.libvirt_apis}
        self.qemu_cscope = self.gen_qemu_cscope()
        self.virsh_cscope = self.gen_virsh_cscope()
        self.mon_funcs = self.get_mon_funcs()

    def get_libvirt_apis(self):
        cmd = 'grep "virDomain[a-zA-Z0-9]*" %s -o' % os.path.join(
            self.src, 'src/libvirt_public.syms')
        return set(sp.check_output(cmd, text=True, shell=True).split('\n'))

    def gen_cscope(self, subdir, name):
        src = os.path.join(self.src, subdir)
        cscope = os.path.join(self.tmpdir, '%s.out' %name)
        cmd = 'cscope -b -f %s -s %s -R' % (cscope, src)
        try:
            sp.check_output(cmd, text=True, shell=True)
        except sp.CalledProcessError as e:
            sys.exit("%s cscope generate failed: %s\nreturn: %d" %
                     (name, cmd, e.returncode))
        return cscope

    def gen_qemu_cscope(self):
        return self.gen_cscope('src/qemu', 'qemu')

    def gen_virsh_cscope(self):
        return self.gen_cscope('tools', 'virsh')

    def get_mon_funcs(self):
        cmd = "cscope -d -L3 %s|grep -v '^[a-zA-Z_0-9]*\.h'|grep -v ATTRIBUTE_ |awk '{print $2}'" % (
            self.makecmd)
        return set(sp.check_output(cmd, text=True, shell=True).split('\n'))

    def get_qmp(self, mon_func):
        qmp_mon_src = os.path.join(self.src, 'src/qemu/qemu_monitor_json.c')
        cmd = """awk '/%s/,/^}/' %s|awk '/%s/,/)/'|grep '"[a-zA-Z:_-]*"' -o |tr '\n' ','""" % (
            mon_func, qmp_mon_src, self.makecmd)
        return sp.check_output(cmd, text=True, shell=True)

    def get_callers(self, fn, cscope):
        cmd = "cscope -d -L3 %s -f %s |grep -v '^[a-zA-Z_0-9]*\.h' | grep -v ATTRIBUTE_ | awk '{print $2}'" % (
            fn, cscope)
        return {x for x in set(sp.check_output(cmd, text=True, shell=True).split('\n')) if x != ''}

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
                callers = self.get_callers(func, cscope)
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
                qmp = self.get_qmp(mon)
                top_callers = self.get_top_callers(mon, self.qemu_cscope)
                callers_api = "\n".join([j.replace('qemu', 'vir', 1) for j in {i for i in top_callers if i in self.qemu_apis}])
                callers_not_api = "\n".join([i for i in top_callers if i not in self.qemu_apis])
                writer.writerow({
                    header[0]: mon,
                    header[1]: qmp,
                    header[2]: callers_api,
                    header[3]: callers_not_api})
