C#
==

The C# version of ASM. can be used with any `Stream`, and is therefore
compatible with many backends (`MemoryStream` for in-memory assembly,
`FileStream` for assembling directly to a file, etc).

Furthermore, it is intended to be fast, and is guaranteed to make **no
allocation**, whether you use `IBufferWriter<byte>` or `Stream`.

## `UseBuffers`
The `UseBuffers` MSBuild property instructs .NET to use `IBufferWriter<byte>`
as first argument instead of `Stream` in all methods.

Performance-wise, this seems equivalent to using `Stream`.

### Benchmarks
Benchmarks are performed using [BenchmarkDotNet](https://github.com/dotnet/BenchmarkDotNet), and yield the following results.

#### Setup
``` ini

BenchmarkDotNet=v0.11.0, OS=Windows 10.0.17134.137 (1803/April2018Update/Redstone4)
Intel Core i7-6700K CPU 4.00GHz (Max: 4.01GHz) (Skylake), 1 CPU, 8 logical and 4 physical cores
Frequency=3914061 Hz, Resolution=255.4891 ns, Timer=TSC
.NET Core SDK=2.1.302
  [Host]   : .NET Core 2.1.2 (CoreCLR 4.6.26628.05, CoreFX 4.6.26629.01), 64bit RyuJIT
  ShortRun : .NET Core 2.1.2 (CoreCLR 4.6.26628.05, CoreFX 4.6.26629.01), 64bit RyuJIT

Job=ShortRun  IterationCount=3  LaunchCount=1  
WarmupCount=3  

```

The following intructions are encoded:
- `ret` (x86): Extremely simple, only one call to `WriteByte` with a constant value.
- `pop eax` (x86): Less simple, but it still only performs one call to `WriteByte`.
- `pop r15d` (x86): Even less simple, with one branch and two separate calls to `WriteByte`.
- `cps #USR` (Arm): More computationaly-heavy, and performs a single call to `WriteLE`.

#### [`BufferWriter`](Asm.Net.Tests/BufferWriter.cs)
|    Method |     Mean |     Error |    StdDev | Allocated |
|---------- |---------:|----------:|----------:|----------:|
|    X86Ret | 3.305 ns | 0.2265 ns | 0.0128 ns |       0 B |
| X86PopEax | 3.895 ns | 0.0357 ns | 0.0020 ns |       0 B |
| X86PopR15 | 7.298 ns | 1.7638 ns | 0.0997 ns |       0 B |
|    ArmCps | 4.132 ns | 0.9399 ns | 0.0531 ns |       0 B |

Note however that these results highly depend on the backing `IBufferWriter<byte>`. For example,
when `[MethodImpl(MethodImplOptions.AggressiveInlining)]` is added to the `GetSpan()` method, the
benchmarks are **very** different:

|    Method |     Mean |     Error |    StdDev | Allocated |
|---------- |---------:|----------:|----------:|----------:|
|    X86Ret | 1.671 ns | 0.0773 ns | 0.0044 ns |       0 B |
| X86PopEax | 2.160 ns | 0.4197 ns | 0.0237 ns |       0 B |
| X86PopR15 | 3.907 ns | 0.4779 ns | 0.0270 ns |       0 B |
|    ArmCps | 2.052 ns | 0.1341 ns | 0.0076 ns |       0 B |

#### `MemoryStream`
|    Method |      Mean |     Error |    StdDev | Allocated |
|---------- |----------:|----------:|----------:|----------:|
|    X86Ret |  3.356 ns | 1.4595 ns | 0.0825 ns |       0 B |
| X86PopEax |  3.872 ns | 0.5465 ns | 0.0309 ns |       0 B |
| X86PopR15 |  6.130 ns | 0.1557 ns | 0.0088 ns |       0 B |
|    ArmCps | 11.176 ns | 0.9019 ns | 0.0510 ns |       0 B |
