import json
import os
import resource
import subprocess
import sys
from bcc.syscall import syscall_name
from time import sleep, strftime, time
import argparse


def get_size_filter(min_size, max_size):
    if min_size is not None and max_size is not None:
        return "if (size < %d || size > %d) return 0;" % (min_size, max_size)
    elif min_size is not None:
        return "if (size < %d) return 0;" % min_size
    elif max_size is not None:
        return "if (size > %d) return 0;" % max_size
    else:
        return ""


def get_stack_flags(kernel_trace):
    if kernel_trace:
        return "0"
    else:
        return "BPF_F_USER_STACK"


def run_command_get_pid(command):
    p = subprocess.Popen(command.split())
    return p.pid


class Arguments:
    def __init__(self, args):
        self.pid = args.pid
        self.command = args.command
        self.interval = args.interval
        self.min_age_ns = 1e6 * args.older
        self.alloc_sample_every_n = args.alloc_sample_rate
        self.top = args.top
        self.min_alloc_size = args.min_alloc_size
        self.max_alloc_size = args.max_alloc_size
        self.obj = args.obj
        self.save_snapshots = args.snapshots

        if self.min_alloc_size is not None and self.max_alloc_size is not None and self.min_alloc_size > self.max_alloc_size:
            print("min_size (-z) can't be greater than max_size (-Z)")
            exit(1)

        if self.command is None and self.pid is None:
            print("Either -p or -c must be specified")
            exit(1)


def parse():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-p", "--pid", type=int, default=-1,
                        help="the PID to trace; if not specified, trace kernel allocs")
    parser.add_argument("interval", nargs="?", default=5, type=int,
                        help="interval in seconds to print outstanding allocations")
    parser.add_argument("-o", "--older", default=500, type=int,
                        help="prune allocations younger than this age in milliseconds")
    parser.add_argument("-c", "--command",
                        help="execute and trace the specified command")
    parser.add_argument("-s", "--alloc-sample-rate", default=1, type=int,
                        help="sample every N-th allocation to decrease the overhead")
    parser.add_argument("-T", "--top", type=int, default=10,
                        help="display only this many top stats")
    parser.add_argument("-z", "--min-alloc-size", type=int,
                        help="capture only allocations larger than this size")
    parser.add_argument("-Z", "--max-alloc-size", type=int,
                        help="capture only allocations smaller than this size")
    parser.add_argument("-O", "--obj", type=str, default="c",
                        help="attach to allocator functions in the specified object")
    parser.add_argument("-S", "--snapshots", default=False, action='store_true',
                        help="save statistics snapshots to ./stats/")
    return Arguments(parser.parse_args())


args = argument_parsing.parse()

# Getting pid
if args.command is not None:
    print(f"Executing '{args.command}' and tracing the resulting process.")
    pid = run_command_get_pid(args.command)
else:
    pid = args.pid

# Constructing probes

bpf = BPF(src_file='ebpf_main.c',
          usdt_contexts=[],
          cflags=[
              "-Wno-macro-redefined",
              f"-DPROCESS_ID={pid}",
              f"-DSAMPLE_EVERY_N={args.alloc_sample_every_n}",
              f"-DPAGE_SIZE={resource.getpagesize()}",
              f"-DFILTER_BY_SIZE={get_size_filter(args.min_alloc_size, args.max_alloc_size)}",
          ])

# Attaching probes

print(f"Attaching to pid {pid}, Ctrl+C to quit.")

for sym in ["malloc", "calloc", "realloc", "mmap", "posix_memalign", "valloc", "memalign", "pvalloc", "aligned_alloc"]:
    bpf.attach_uprobe(name=args.obj, sym=sym, fn_name=sym + "_enter", pid=pid)
    bpf.attach_uretprobe(name=args.obj, sym=sym, fn_name=sym + "_exit", pid=pid)

bpf.attach_uprobe(name=args.obj, sym="free", fn_name="free_enter", pid=pid)
bpf.attach_uprobe(name=args.obj, sym="munmap", fn_name="munmap_enter", pid=pid)

# kernel cache probes
bpf.attach_kprobe(event='kmem_cache_alloc_lru', fn_name='trace_cache_alloc')
bpf.attach_kprobe(event='kmem_cache_alloc_bulk', fn_name='trace_cache_alloc')
bpf.attach_kprobe(event='kmem_cache_alloc_node', fn_name='trace_cache_alloc')

bpf.attach_kprobe(event='kmem_cache_free', fn_name='trace_cache_free')
bpf.attach_kprobe(event='kmem_cache_free_bulk', fn_name='trace_cache_free')


class Allocation(object):
    def __init__(self, stack, size):
        self.stack = stack
        self.count = 1
        self.size = size

    def update(self, size):
        self.count += 1
        self.size += size


def print_outstanding():
    print(f"Top {args.top} stacks with outstanding allocations:")
    alloc_info = {}
    allocs = bpf["allocs"]
    stack_traces = bpf["stack_traces"]
    for address, info in sorted(allocs.items(), key=lambda a: a[1].size):
        if BPF.monotonic_time() - args.min_age_ns < info.timestamp_ns:
            continue
        if info.stack_id < 0:
            continue
        if info.stack_id in alloc_info:
            alloc_info[info.stack_id].update(info.size)
        else:
            stack = list(stack_traces.walk(info.stack_id))
            combined = []
            for addr in stack:
                func_name = bpf.sym(addr, pid, show_module=True, show_offset=True)
                formatted_address = ('0x' + format(addr, '016x') + '\t').encode('utf-8')
                combined.append(formatted_address + func_name)
            alloc_info[info.stack_id] = Allocation(combined, info.size)
        print(f"\taddr = {address.value} size = {info.size}")
    to_show = sorted(alloc_info.values(), key=lambda a: a.size)[-args.top:]
    for alloc in to_show:
        stack = b"\n\t\t".join(alloc.stack).decode("ascii")
        print(f"\t{alloc.size} bytes in {alloc.count} allocations from stack\n\t\t{stack}")


def get_outstanding():
    alloc_info = {}
    allocs = bpf["allocs"]
    stack_traces = bpf["stack_traces"]
    memory = {}
    for address, info in sorted(allocs.items(), key=lambda a: a[1].size):
        if BPF.monotonic_time() - args.min_age_ns < info.timestamp_ns:
            continue
        if info.stack_id < 0:
            continue
        if info.stack_id in alloc_info:
            alloc_info[info.stack_id].update(info.size)
        else:
            stack = list(stack_traces.walk(info.stack_id))
            combined = []
            for addr in stack:
                func_name = bpf.sym(addr, pid, show_module=True, show_offset=True)
                formatted_address = ('0x' + format(addr, '016x') + '\t').encode('utf-8')
                combined.append(formatted_address + func_name)
            alloc_info[info.stack_id] = Allocation(combined, info.size)
        memory['addr'] = address.value
        memory['size'] = info.size
    return list(
        map(lambda alloc: {'stack': [s.decode('ascii') for s in alloc.stack], 'size': alloc.size, 'count': alloc.count},
            sorted(alloc_info.values(), key=lambda a: a.size)[-args.top:]))


class CombinedAlloc(object):
    def __init__(self, item):
        self.stack_id = item[0]
        self.free_size = item[1].free_size
        self.alloc_size = item[1].alloc_size
        self.number_of_frees = item[1].number_of_frees
        self.number_of_allocs = item[1].number_of_allocs

    def key(self):
        return self.alloc_size - self.free_size

    def __str__(self):
        return f"CombinedAlloc(stack_id={self.stack_id},\n" \
               f"\t free_size={self.free_size},\n" \
               f"\t alloc_size={self.alloc_size},\n" \
               f"\t number_of_frees={self.number_of_frees},\n" \
               f"\t number_of_allocs={self.number_of_allocs})\n"

    def __repr__(self):
        return self.__str__()

    def is_positive(self):
        return self.alloc_size > self.free_size


def print_statistics():
    stack_traces = bpf["stack_traces"]
    print("stack traces", len(list(stack_traces.items())))
    combined_alloc = list(
        sorted(
            map(CombinedAlloc, bpf["combined_allocs"].items()),
            key=lambda a: a.key(),
        )
    )
    memory = sum((c.alloc_size - c.free_size for c in combined_alloc)) / 1024
    print("overall, allocated", memory, "kb in", len(combined_alloc), "allocations")
    entries = []
    for allocation in combined_alloc[:args.top]:
        trace = get_trace_info(stack_traces, allocation.stack_id.value)
        entry = f"\t{allocation.alloc_size - allocation.free_size} bytes in " \
                f"{allocation.number_of_allocs - allocation.number_of_frees}" \
                f" allocations from stack ({allocation.number_of_allocs + allocation.number_of_frees} allocs/frees)" \
                f"\n\t\t{trace}"
        entries.append(entry)

    print(f"Top {args.top} stacks with outstanding allocations:")
    print('\n'.join(reversed(entries)))


def get_statistics():
    stack_traces = bpf["stack_traces"]
    combined_alloc = list(
        sorted(
            map(CombinedAlloc, bpf["combined_allocs"].items()),
            key=lambda a: a.key(),
        )
    )
    memory = sum((c.alloc_size - c.free_size for c in combined_alloc))
    entries = []
    for allocation in combined_alloc:
        entries.append({
            'alloc_size': allocation.alloc_size,
            'free_size': allocation.free_size,
            'number_of_allocs': allocation.number_of_allocs,
            'number_of_frees': allocation.number_of_frees,
            'trace': get_trace_info_as_list(stack_traces, allocation.stack_id.value),
        })
    return {
        "memory": memory,
        "stacks": list(reversed(entries)),
        "stack_traces": len(list(stack_traces.items()))
    }


def get_trace_info(stack_traces, stack_id):
    trace = []
    for addr in walk_trace(stack_traces, stack_id):
        sym = bpf.sym(addr, pid, show_module=True, show_offset=True)
        trace.append(sym.decode())

    trace = "\n\t\t".join(trace)
    if not trace:
        trace = "stack information lost"
    return trace


def get_trace_info_as_list(stack_traces, stack_id):
    trace = []
    for addr in walk_trace(stack_traces, stack_id):
        sym = bpf.sym(addr, pid, show_module=True, show_offset=True)
        trace.append(sym.decode())

    return trace


def walk_trace(stack_traces, stack_id):
    try:
        return stack_traces.walk(stack_id)
    except KeyError:
        return []


def print_outstanding_kernel_cache():
    kernel_cache_allocs = list(
        sorted(filter(lambda a: a[1].alloc_size > a[1].free_size, bpf['kernel_cache_counts'].items()),
               key=lambda a: a[1].alloc_size - a[1].free_size)
    )[:args.top]
    if not kernel_cache_allocs:
        return
    print("---------------- Kernel Caches ---------------")
    for (k, v) in kernel_cache_allocs:
        print("Cache", str(k.name, "utf-8"), v.alloc_count - v.free_count, v.alloc_size - v.free_size)


def gernel_kernel_cache():
    kernel_cache_allocs = list(
        sorted(filter(lambda a: a[1].alloc_size > a[1].free_size, bpf['kernel_cache_counts'].items()),
               key=lambda a: a[1].alloc_size - a[1].free_size)
    )[:args.top]
    if not kernel_cache_allocs:
        return
    caches = []
    for (k, v) in kernel_cache_allocs:
        caches.append({
            'name': str(k.name, "utf-8"),
            'alloc_count': v.alloc_count,
            'free_count': v.free_count,
            'alloc_size': v.alloc_size,
            'free_size': v.free_size,
        })
    return caches


def print_syscalls():
    syscall_counts = bpf["syscall_counts"]
    print("SYSCALL                   COUNT             TIME")
    for k, v in sorted(syscall_counts.items(), key=lambda kv: -kv[1].total_ns)[:args.top]:
        print("%-22s %8d %16.3f" % (system_call_name(k), v.count, v.total_ns / 1e3))
    syscall_counts.clear()


def get_syscalls():
    syscall_counts = bpf["syscall_counts"]
    syscalls = []
    for k, v in sorted(syscall_counts.items(), key=lambda kv: -kv[1].total_ns)[:args.top]:
        syscalls.append({
            'name': system_call_name(k),
            'count': v.count,
            'total_ns': v.total_ns,
        })
    syscall_counts.clear()
    return syscalls


def system_call_name(k):
    return syscall_name(k.value).decode('ascii')


def print_time():
    print("[%s]" % strftime("%H:%M:%S"))


def save_snapshot():
    current_time_millis = int(round(time() * 1000))
    stats = get_statistics()
    outstanding = get_outstanding()
    kernel_caches = gernel_kernel_cache()
    syscalls = get_syscalls()
    snapshot = {
        'time': current_time_millis,
        'stats': stats,
        'outstanding': outstanding,
        'kernel_caches': kernel_caches,
        'syscalls': syscalls,
    }
    os.makedirs('snapshots', exist_ok=True)
    with open(f'snapshots/{current_time_millis}.json', 'w') as outfile:
        json.dump(snapshot, outfile)


while True:
    try:
        sleep(args.interval)
    except KeyboardInterrupt:
        exit()
    if args.save_snapshots:
        save_snapshot()
    else:
        print_time()
        print_statistics()
        print_outstanding()
        print_outstanding_kernel_cache()
        print_syscalls()
        print()
        sys.stdout.flush()
