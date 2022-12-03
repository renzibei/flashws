# FlashWS

This is a performance-oriented implementation of WebSocket. Strive for lowest
latency and high throughput.

Our library supports DPDK (Data Plane Development Kit, a kernel-bypass network
library).

## Design

We abstracted the TCP layer once. Various implementations are available for TCP.
Currently we have implemented [F-Stack](https://github.com/F-Stack/f-stack)
(TCP/IP network library based on DPDK) and
POSIX API. It should be noted that we do not recommend the implementation of the
POSIX API, because we have not optimized it.

Technologies including Zero Copy, Huge Page, SIMD, etc. are used to optimize our
implementation.

## Dependency

Our current implementation is based on F-Stack to obtain the TCP/IP protocol
stack. So you need to install F-Stack and DPDK beforehand, unless you want to
use POSIX implementation (and then the advantage is gone). See the website of
[F-Stack](https://github.com/F-Stack/f-stack) for details.

Also, currently we also need openssl.

## Build

This is a head-only library, all you need is the installation of dependencies
and properly include this code directory.

After you have installed the dependent libraries,

```
git clone https://github.com/renzibei/flashws
cd flashws
git submodule update --init --recursive
```

Then you can compile the tests and examples.

```
cd tests
cd ws-echo
mkdir build
cmake ..
make -j6
```

## Performance
You can take a look at the benchmark
[ws-benchmark](https://github.com/renzibei/ws-benchmark).