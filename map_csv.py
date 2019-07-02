#!/usr/bin/python3
import subprocess
import argparse
import os
import argparse
import csv
from functools import reduce


def get_apis_from_src(src_dir):
    cmd = 'grep "virDomain[a-zA-Z0-9]*" %s -o|sed "s/^vir/qemu/"' % os.path.join(
        src_dir, 'libvirt_public.syms')
    return set(subprocess.getoutput(cmd).split('\n'))


def gen_cscope(src_dir):
    os.system(
        "find %s -name *.c -o -name *.h > cscope.files" % os.path.join(src_dir, 'qemu'))
    os.system('cscope -b -q -k')


def get_mon_functions(makecmd_wrapper):
    cmd = "cscope -d -L3 %s |grep -v '^[a-zA-Z_0-9]*\.h' | grep -v ATTRIBUTE_ | awk '{print $2}'" % (
        makecmd_wrapper)
    #print("get_mon_functions cmd: %s" % cmd)
    return set(subprocess.getoutput(cmd).split('\n'))


def get_qmp(mon_wrapper, makecmd_wrapper, src_dir):
    qmp_mon_src = os.path.join(src_dir, 'qemu', 'qemu_monitor_json.c')
    cmd = """awk '/%s/,/^}/' %s|awk '/%s/,/)/'|grep '\"[a-zA-Z:_-]*\"' -o |tr '\n' ','""" % (
        mon_wrapper, qmp_mon_src, makecmd_wrapper)
    return subprocess.getoutput(cmd)


def get_parent_callers(fn):
    cmd = "cscope -d -L3 %s |grep -v '^[a-zA-Z_0-9]*\.h' | grep -v ATTRIBUTE_ | awk '{print $2}'" % (
        fn)
    callers = {x for x in set(subprocess.getoutput(cmd).split('\n')) if x != ''}
    if not callers or callers == {fn}:
        return {fn}
    return callers


def get_top_callers(fns):
    callers = fns
    while True:
        next_callers = set(reduce(lambda x, y: x | y, map(
            lambda x: get_parent_callers(x), callers)))
        if callers == next_callers:
            return callers
        callers = next_callers


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--source', help='The source directory of libvirt',
                        required=True, type=str)
    parser.add_argument(
        '-o', '--output', help='The output csv file', default='out.csv', type=str)
    args = parser.parse_args()

    makecmd_wrapper = 'qemuMonitorJSONMakeCommand'
    src_dir = args.source

    gen_cscope(src_dir)
    mon_wrappers = get_mon_functions(makecmd_wrapper)

    with open(args.output, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=[
                                "Monitor Wrapper", "QMP", "Qemu driver caller", "Callers not in qemu drivers"], delimiter='|')
        writer.writeheader()

        for mon_wrapper in mon_wrappers:
            print("Processing mon wrapper: %s" % mon_wrapper)
            qmp = get_qmp(mon_wrapper, makecmd_wrapper, src_dir)
            apis = get_apis_from_src(src_dir)
            mon_callers = get_top_callers({mon_wrapper})
            mon_callers_inapi_str = '\n'.join(
                [caller for caller in mon_callers if caller in apis])
            mon_callers_notinapi_str = '\n'.join(
                [caller for caller in mon_callers if caller not in apis])
            writer.writerow({
                "Monitor Wrapper": mon_wrapper,
                "QMP": qmp,
                "Qemu driver caller": mon_callers_inapi_str,
                "Callers not in qemu drivers": mon_callers_notinapi_str})
