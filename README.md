# rs_sys_hook

Rust template of [not-wlan/instrumentation-callbacks](https://github.com/not-wlan/instrumentation-callbacks/blob/master/minwin/minwin.cpp) to hook ntapi functions using `nt_set_information_process` and `ProcessInstrumentationCallbackInformation`

By default will just hook NtQueryVirtualMemory to return 0 instead of access violation:
```
[SHOOK] NtQueryVirtualMemory: 0xc0000005
[SHOOK] NtSetInformationProcess - Adding callback: 0x0
[SHOOK] function: [90]
        return value: 0xffffffffc0000005
        return address: 0x7ffb8294d2b4

[SHOOK] NtQueryVirtualMemory - Modified callback: 0x0
```

Files and imports used as dependencies in other projects and require very few changes to be compatible with `no_std`