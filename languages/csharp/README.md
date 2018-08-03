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

Right now, however, this introduces a huge performance loss.

### Benchmarks: [`BufferWriter`](Asm.Net.Tests/BufferWriter.cs)
``` ini

BenchmarkDotNet=v0.11.0, OS=Windows 10.0.17134.165 (1803/April2018Update/Redstone4)
Intel Core i5-6300U CPU 2.40GHz (Skylake), 1 CPU, 4 logical and 2 physical cores
Frequency=2437500 Hz, Resolution=410.2564 ns, Timer=TSC
.NET Core SDK=2.1.4
  [Host]   : .NET Core 2.0.5 (CoreCLR 4.6.26020.03, CoreFX 4.6.26018.01), 64bit RyuJIT
  ShortRun : .NET Core 2.0.5 (CoreCLR 4.6.26020.03, CoreFX 4.6.26018.01), 64bit RyuJIT

Job=ShortRun  IterationCount=3  LaunchCount=1  
WarmupCount=3  

```
| Method |     Mean |    Error |    StdDev | Allocated |
|------- |---------:|---------:|----------:|----------:|
| X86Ret | 25.99 ns | 6.255 ns | 0.3534 ns |       0 B |

### Benchmarks: `MemoryStream`
``` ini

BenchmarkDotNet=v0.11.0, OS=Windows 10.0.17134.165 (1803/April2018Update/Redstone4)
Intel Core i5-6300U CPU 2.40GHz (Skylake), 1 CPU, 4 logical and 2 physical cores
Frequency=2437500 Hz, Resolution=410.2564 ns, Timer=TSC
.NET Core SDK=2.1.4
  [Host]   : .NET Core 2.0.5 (CoreCLR 4.6.26020.03, CoreFX 4.6.26018.01), 64bit RyuJIT
  ShortRun : .NET Core 2.0.5 (CoreCLR 4.6.26020.03, CoreFX 4.6.26018.01), 64bit RyuJIT

Job=ShortRun  IterationCount=3  LaunchCount=1  
WarmupCount=3  

```
| Method |     Mean |     Error |    StdDev | Allocated |
|------- |---------:|----------:|----------:|----------:|
| X86Ret | 4.935 ns | 0.5868 ns | 0.0332 ns |       0 B |
