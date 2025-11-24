from seccomp import SyscallFilter, ALLOW, KILL
def allow_many(f, names):
    for s in names:
        try: f.add_rule(ALLOW, s)
        except: pass

def apply_ssh_filter():
    f = SyscallFilter(defaction=KILL)
    allow_many(f, ["read","write","exit","futex","close","accept","accept4","bind","listen","socket",
                   "recvfrom","sendto","recvmsg","sendmsg","getsockname","getpeername","open","openat",
                   "stat","fstat","mmap","mprotect","brk","rt_sigaction","rt_sigprocmask","ioctl"])
    f.load()

def apply_http_filter():
    f = SyscallFilter(defaction=KILL)
    allow_many(f, ["read","write","exit","futex","close","bind","listen","socket","accept",
                   "open","openat","stat","fstat","sendto","recvfrom","recvmsg","sendmsg","getcwd"])
    f.load()
