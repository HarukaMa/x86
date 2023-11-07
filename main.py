import sys

from exc import Exited
from machine import Machine
from loader import load_pe64, load_pe32


def main():
    # noinspection PyArgumentEqualDefault
    machine = Machine(debug_start=0, trace_start=None)
    load_pe64(machine, sys.argv[1])
    # load_pe32(machine, "/Users/MrX/Downloads/chuniApp_c+_origin.exe")
    # load_pe64(machine, "/Users/MrX/Downloads/amdaemon.exe")
    # load_pe64(machine, "/Users/MrX/Downloads/alls/SEGA/System/installed/0001_StandardCommon_040/System/sgimagemount.exe")
    # load_pe64(machine, "/Volumes/SanDiskX400/ong_rp/package/amdaemon_dump_SCY.exe", ["-c", "a"])
    # load_pe64(machine, "/Volumes/SanDiskX400/aca/0001_StandardCommon_064/System/sgimagemount_dump_scy.exe")
    # load_pe64(machine, "/tmp/a.exe")
    try:
        while True:
            machine.step()
            if (machine.debug and machine.inst_count > machine.debug_start) or machine.step_into:
                machine.cpu.dump()
                pass
            else:
                if machine.inst_count % 100000 == 0:
                    print(machine.inst_count)
    except Exited as e:
        print("Process finished with exit code %s" % e.status)
if __name__ == '__main__':
    main()
