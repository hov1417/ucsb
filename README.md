<h1 align="center">Unbranded Cloud Serving Benchmark eBPF</h1>
<h3 align="center">
eBPF enhanced fork of <a href="https://github.com/unum-cloud/ucsb">UCSV</a><br/>
<br/>
</h3>
<br/>

---

For detailed documentation please refer to the parent repository.
Here are modifications done to the UCSB

This fork adds optional eBPF-based profiling, which can be enabled with `--with-ebpf` and `--with-ebpf-memory` flags,
before execution make sure you have `bcc` [installed](https://github.com/iovisor/bcc/blob/master/INSTALL.md) at least version 0.21.0.

Raw collected metrics are available in [results](results) and [results-single-threaded](results-single-threaded) for single threaded.
Some breakdown of results is available in [user-vs-kernel-time.ipynb](user-vs-kernel-time.ipynb).