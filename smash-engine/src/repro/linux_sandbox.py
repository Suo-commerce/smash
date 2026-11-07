"""Trusted exec-time Linux containment; never evaluates artifact text as code."""
import ctypes
import errno
import json
import os
import resource
import sys


EXECUTE = 1 << 0
WRITE_FILE = 1 << 1
READ_FILE = 1 << 2
READ_DIR = 1 << 3
READ_WRITE_FS = (1 << 14) - 1
LANDLOCK_RULESET = 444
LANDLOCK_ADD_RULE = 445
LANDLOCK_RESTRICT = 446
PATH_BENEATH = 1
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_FILTER = 2
ARCHES = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}
SOCKET_SYSCALLS = {
    "x86_64": {41, 42, 43, 44, 49, 53, 288},  # socket..accept4/connect/bind/socketpair
    "aarch64": {198, 203, 200, 203, 202, 242, 199},
}


def fail(message):
    os.write(2, ("M2_SETUP_FAILED: " + message + "\n").encode())
    os._exit(125)


def landlock(libc, rules):
    attr = ctypes.Structure
    class Attr(attr):
        _fields_ = [("handled_access_fs", ctypes.c_uint64),
                    ("handled_access_net", ctypes.c_uint64)]
    class Beneath(attr):
        _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]
    flags = READ_WRITE_FS
    abi = libc.syscall(LANDLOCK_RULESET, None, 0, 1)
    if abi < 1:
        fail("landlock unavailable")

    attr = Attr(flags, 0)
    ruleset = libc.syscall(LANDLOCK_RULESET, ctypes.byref(attr), ctypes.sizeof(attr), 0)
    if ruleset < 0:
        fail("landlock ruleset: " + os.strerror(ctypes.get_errno()))
    for path, access, directory in rules:
        oflags = os.O_PATH | os.O_CLOEXEC
        if directory:
            oflags |= os.O_DIRECTORY
        try:
            parent = os.open(path, oflags)
        except OSError as error:
            os.close(ruleset)
            fail("open trusted path: " + error.strerror)
        allowed = access
        if abi < 2:
            allowed &= ~(1 << 13)
        rule = Beneath(allowed, parent)
        result = libc.syscall(LANDLOCK_ADD_RULE, ruleset, PATH_BENEATH,
                              ctypes.byref(rule), 0)
        os.close(parent)
        if result != 0:
            os.close(ruleset)
            fail("landlock path rule for " + path + ": " + os.strerror(ctypes.get_errno()))
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        fail("no_new_privs before landlock")
    if libc.syscall(LANDLOCK_RESTRICT, ruleset, 0) != 0:
        fail("landlock restrict: " + os.strerror(ctypes.get_errno()))
    os.close(ruleset)


def seccomp(libc, arguments, post_exec=False, validate_host=True):
    arch = arguments["arch"]
    if arch not in ARCHES:
        fail("unsupported architecture")
    if validate_host:
        # Do this before entering a sealed interpreter. Some Python versions
        # initialize unrelated modules (and even local sockets) with platform.
        import platform
        if platform.machine() != arch:
            fail("unsupported architecture")
    class Filter(ctypes.Structure):
        _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_ubyte),
                    ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]
    class Program(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ushort), ("filter", ctypes.POINTER(Filter))]
    BPF_LD_W_ABS = 0x20
    BPF_JMP_JEQ_K = 0x15
    BPF_RET_K = 0x06
    KILL = 0x00000000
    single_driver = arguments.get("single_driver", False)
    # M5's sealed Python launcher can ignore failed local socket probes made by
    # runtime library initialization. No socket or process operation is allowed;
    # retain the existing M2 kill behavior outside this explicit profile.
    DENIED = (0x00050000 | errno.EPERM) if single_driver else KILL
    ALLOW = 0x7FFF0000
    # Validate architecture then deny all network creation/control syscalls and
    # process-group escape. The initial setsid has already been performed by Rust.
    filters = [Filter(BPF_LD_W_ABS, 0, 0, 4),
               Filter(BPF_JMP_JEQ_K, 1, 0, ARCHES[arch]),
               Filter(BPF_RET_K, 0, 0, KILL),
               Filter(BPF_LD_W_ABS, 0, 0, 0)]
    blocked = SOCKET_SYSCALLS[arch]
    if arch == "x86_64":
        blocked |= {165, 166}  # mount, umount2
        setsid, setpgid = 112, 109
        creation = {56, 57, 58, 435}
        execution = (59, 322)
    else:
        blocked |= {40, 39}
        setsid, setpgid = 157, 155
        creation = {220, 435}  # clone/clone3; no fork/vfork on aarch64
        execution = (221, 259)
    # execveat is never needed. execve alone is restricted to the helper's
    # initial Python bootstrap; the M5 launcher adds it before driver code.
    if single_driver:
        blocked |= creation | {execution[1]}
    if post_exec:
        if not single_driver:
            fail("post-exec filter requires the M5 single-driver profile")
        blocked |= creation | set(execution)
    for syscall in blocked | {setsid, setpgid}:
        filters += [Filter(BPF_JMP_JEQ_K, 0, 1, syscall),
                    Filter(BPF_RET_K, 0, 0, DENIED)]
    filters.append(Filter(BPF_RET_K, 0, 0, ALLOW))
    array = (Filter * len(filters))(*filters)
    program = Program(len(filters), array)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        fail("no_new_privs before seccomp")
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_FILTER, ctypes.byref(program), 0, 0) != 0:
        fail("seccomp: " + os.strerror(ctypes.get_errno()))


def main():
    if os.geteuid() == 0:
        fail("root cannot provide this provider's process accounting contract")
    with open(sys.argv[1], encoding="utf-8") as config_file:
        config = json.load(config_file)
    os.close(0)
    # stdin is already /dev/null. Apply only one helper namespace; no fork after
    # this point in the helper itself. Children inherit both security layers.
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        fail("only 64-bit Linux is implemented")
    # The current rule set deliberately omits discretionary net flags: seccomp
    # denies all socket creation, rather than merely claiming a Landlock flag.
    rules = []
    for path in config["read_roots"]:
        if not os.path.isdir(path):
            fail("read root is not a directory")
        rules.append((path, EXECUTE | READ_FILE | READ_DIR, True))
    rules.append((config["output_root"], READ_WRITE_FS, True))
    for path in config["write_roots"]:
        if not os.path.isdir(path):
            fail("write root is not a directory")
        rules.append((path, READ_WRITE_FS, True))
    for path in config["read_files"]:
        if not os.path.isfile(path):
            fail("read file is not a regular file")
        rules.append((path, EXECUTE | READ_FILE, False))
    if config["contained"]:
        landlock(libc, rules)
    limits = config["limits"]
    resource.setrlimit(resource.RLIMIT_CPU, (limits["cpu_s"], limits["cpu_s"]))
    resource.setrlimit(resource.RLIMIT_AS, (limits["memory_bytes"],) * 2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (limits["output_bytes"],) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_NPROC, (limits["processes"],) * 2)
    if config["contained"]:
        seccomp(libc, config)
    os.chdir(config["output_root"])
    env = {"PATH": config["path"], "LANG": "C", "LC_ALL": "C",
           "TMPDIR": config["output_root"], "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONNOUSERSITE": "1", "PYTHONHASHSEED": "0"}
    env.update(config["environment"])

    os.execve(config["argv"][0], config["argv"], env)


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        fail(type(error).__name__ + ": " + str(error))
