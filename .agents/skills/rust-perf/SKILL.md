---
name: rust-perf
description: Rust performance optimization, from The Rust Performance Book. Use when speeding up Rust code (runtime, memory, binary size, compile time), choosing Cargo release-profile settings, reading a profile or benchmark, or reducing allocations, hashing, bounds-check, I/O or inlining cost.
---

# Rust Performance

Digest of [The Rust Performance Book](https://nnethercote.github.io/perf-book/) (Nicholas Nethercote et al.), with the unmodified chapter sources in `references/` (from <https://github.com/nnethercote/perf-book/tree/master/src>). Each chapter below has a summary and a pointer to its `references/` file, which holds the code samples, caveats and real-world PR links the summary omits.

## Workflow

1. **Release build.** Confirm the measured binary comes from `--release` (dev builds are often 10-100x slower). Done when the build output says `[optimized]`.
2. **Baseline.** Measure a realistic workload before touching code ([benchmarking](#benchmarking), [profiling](#profiling)). Done when you hold a number to compare against.
3. **Hot spot.** Profile and name the hot function, allocation site or type. Optimize only hot code. Done when a profiler output (not a guess) points at it.
4. **Chapter.** Match the finding to a chapter below and read its page before editing.
5. **One change, re-measure.** Apply one change at a time and keep it only if the measurement improves. Inlining, `SmallVec`, alternative hashers and `parking_lot` can all come out slower.

## Chapters

### Introduction
Page: [`references/introduction.md`](references/introduction.md). Scope: runtime speed, memory use, binary size (and compile times). Terse, practical, aimed at intermediate/advanced users; no substitute for a general optimization guide. Read for scope questions only.

### Benchmarking
Page: [`references/benchmarking.md`](references/benchmarking.md). Use real-world workloads; microbenchmarks and stress tests in moderation. Harnesses: built-in `#[bench]` (nightly only), Criterion, Divan, Hyperfine (any command), Bencher (CI), Gungraun, custom (rustc-perf). Wall-time is intuitive but noisy (memory layout shifts); cycles or instruction counts have lower variance. Mediocre benchmarking beats none. Read when choosing a harness or metric.

### Build Configuration
Page: [`references/build-configuration.md`](references/build-configuration.md). Biggest wins need no code change; Cargo reads profile settings only from the workspace root `Cargo.toml` (binary crates matter, library crates don't). Validate every change by benchmark.
- **Release builds**: `--release` is the single most important setting.
- **Max speed**: `codegen-units = 1`; `lto = "fat"` (or `"thin"`; `false` keeps thin-local LTO, `"off"` disables); alternative allocator (`tikv-jemallocator` on Linux/Mac, optionally with THP via `MALLOC_CONF`; `mimalloc` cross-platform); `-C target-cpu=native` when portability is not needed; PGO via `cargo-pgo` (not available through `cargo install` distribution).
- **Min binary size**: `opt-level = "z"` (or `"s"`), `panic = "abort"`, `strip = "symbols"` (hurts debugging/backtraces); see `min-sized-rust`.
- **Min compile time**: faster linker (lld, mold, wild on Linux; lld on Windows; none needed on Mac), no tradeoff; `debug = false` or `"line-tables-only"` in `[profile.dev]` (20-40% faster); nightly parallel front-end `-Zthreads=8`; nightly Cranelift back-end for dev builds; custom profiles between `dev` and `release`.
- `cargo-wizard` picks a configuration interactively.

Read for exact TOML/flags, trade-offs, or the closing recommendations list.

### Linting
Page: [`references/linting.md`](references/linting.md). `cargo clippy` catches perf anti-patterns (filter the lint list to the "Perf" group); perf lints usually also simplify code. Some style lints help speed too (`ptr_arg`: `&mut Vec<T>` to `&mut [T]`). Use `disallowed_types` in `clippy.toml` to ban `std` `HashMap`/`HashSet` (or other swapped-out types) after choosing an alternative. The rest of the book omits problems Clippy flags by default. Read for the `clippy.toml` setup.

### Profiling
Page: [`references/profiling.md`](references/profiling.md). Profilers: perf (+ Hotspot/Firefox Profiler), Instruments (macOS), VTune, AMD μProf, samply, flamegraph, Cachegrind/Callgrind (instruction counts, simulated cache), DHAT / dhat-rs (allocations, memcpy), heaptrack, bytehound, `counts` (ad hoc `eprintln!` frequency counts), Coz (causal). Prep for good output: `debug = "line-tables-only"` in the release profile; std library has no debug info (build own toolchain with `debuginfo-level = 1`, or `build-std`); `-C force-frame-pointers=yes` for stack traces; demangle with `rustfilt` or switch to `-C symbol-mangling-version=v0`. Read for profiler platform support and setup.

### Inlining
Page: [`references/inlining.md`](references/inlining.md). Attributes: none (compiler decides), `#[inline]`, `#[inline(always)]`, `#[inline(never)]`; all are hints, and inlining is non-transitive (`f` calling `g` needs both marked). Best candidates: very small functions or single-call-site functions. Cachegrind shows a function is inlined iff its first and last lines have no event counts. For a large function with one hot call site, split into an `#[inline(always)]` variant (hot site) and an `#[inline(never)]` wrapper (cold sites). Outlining: move rare code into a `#[cold]` function. Always re-measure; it can regress speed and compile time. Read for the split pattern and Cachegrind reading.

### Hashing
Page: [`references/hashing.md`](references/hashing.md). Default `HashMap`/`HashSet` use SipHash 1-3: DoS-resistant but slow for short keys. If hashing is hot and HashDoS is not a concern, try `rustc-hash` (`FxHashMap`, very fast, low quality), `fnv`, `ahash`, or `nohash_hasher` for already-random integer keys; try several, since results vary widely (rustc saw +6% and -84% across swaps). Derived `Hash` hashes field by field; `zerocopy`/`bytemuck` `ByteHash` can hash raw bytes (advanced, measure). Ban the std types with Clippy. Read for crate comparison and rustc numbers.

### Heap Allocations
Page: [`references/heap-allocations.md`](references/heap-allocations.md). Allocation is moderately costly (locks, bookkeeping, syscalls). If `malloc`/`free` are hot, cut allocation rate (DHAT; ~10 fewer allocs per million instructions gave ~1% in rustc) or switch allocator. Techniques:
- `Box`: little scope except boxing fields to shrink types. `Rc`/`Arc`: sharing saves memory, but rarely-shared values add allocations; `clone` only bumps a count.
- `Vec`: growth is 0, 4, 8, 16...; use `with_capacity`/`reserve`/`reserve_exact` when the size is known; `SmallVec` for many short vectors (not always faster), `ArrayVec` when the max length is known; `shrink_to_fit` may reallocate. Print length distributions with `eprintln!` + `counts` first.
- `String`: `with_capacity`, `smallstr`, `smartstring` (no heap under 24 bytes); `format!` always allocates, so prefer literals or `format_args!`.
- Hash tables: single allocation, has `with_capacity`.
- `clone`: usually allocates; use `clone_from` to reuse an existing allocation; remove unnecessary hot clones.
- `to_owned`/`to_string`: store borrowed data (with lifetimes) only when measured worthwhile.
- `Cow`: mixed borrowed/owned data, clone-on-write via `to_mut`.
- Reuse collections: pass `&mut Vec`, or keep a workhorse collection and `clear()` it.
- Reading lines: `BufRead::lines` allocates per line; use `read_line` with a reused `String`.
- Prevent regressions with `dhat-rs` heap usage tests.

Read for code examples of `Cow`, `clone_from`, workhorse collections and line reading.

### Type Sizes
Page: [`references/type-sizes.md`](references/type-sizes.md). Shrinking oft-instantiated types cuts memory traffic and cache pressure; types over 128 bytes are copied with `memcpy` (DHAT copy profiling finds these). Inspect with `size_of` or nightly `-Zprint-type-sizes` (or `top-type-sizes`). The compiler already reorders fields (unless `#[repr(C)]`). Shrink by: boxing outsized enum variants (rare variants win most), smaller integers for indices (`u32`/`u16`/`u8`), `Box<[T]>` instead of `Vec<T>` (two words, drops excess capacity), `ThinVec` (one word, good for often-empty vectors). Guard with `static_assertions::assert_eq_size!` under `cfg(target_arch = "x86_64")`. Read for `-Zprint-type-sizes` output and examples.

### Standard Library Types
Page: [`references/standard-library-types.md`](references/standard-library-types.md). Read the docs of `Vec`, `Option`, `Result`, `Rc`/`Arc` for perf-relevant methods. `vec![0; n]` is the best zero-filled vector; `Vec::remove` is O(n) while `swap_remove` is O(1) (unordered); `retain` removes many items efficiently. `ok_or`, `map_or`, `unwrap_or`, `Result::or` evaluate arguments eagerly, so use the `_else` forms when the argument is expensive. `Rc::make_mut`/`Arc::make_mut` give clone-on-write. `parking_lot` alternatives to `Mutex`/`RwLock`/`Condvar`/`Once` used to be clearly faster; std has caught up on some platforms, so measure. Read for the eager/lazy example.

### Iterators
Page: [`references/iterators.md`](references/iterators.md). Skip `collect` when the result is only iterated again; return `impl Iterator` instead of `Vec`; use `extend` rather than collect + `append`; implement `size_hint`/`ExactSizeIterator::len` on custom iterators. `chain` can be slow in hot loops; `filter_map` can beat `filter` + `map`. Prefer `chunks_exact` over `chunks` (use `remainder()` for the tail), likewise the `rchunks`/`_mut` variants. `iter().copied()` over small types can improve LLVM output (advanced; check the machine code). Read for the chunk-iterator family and lifetime notes on `impl Iterator` returns.

### Bounds Checks
Page: [`references/bounds-checks.md`](references/bounds-checks.md). Indexing into slices/`Vec` is bounds-checked; impact is smaller than expected, but matters in hot loops. Safe fixes: iterate instead of index, slice the `Vec` before the loop, assert index ranges up front. See the Bounds Check Cookbook. Last resort: `get_unchecked`/`get_unchecked_mut` (unsafe). Read for the cookbook link and examples.

### I/O
Page: [`references/io.md`](references/io.md). `print!`/`println!` lock stdout on every call: lock once (`stdout().lock()` + `writeln!`); same for stdin/stderr. File and socket I/O is unbuffered: wrap in `BufWriter`/`BufReader` (call `flush()` explicitly to surface errors); combine locking and buffering for heavy stdout use. Buffered readers use `BufRead`, which enables `read_line`/`lines`; avoid per-line allocation (see [Heap Allocations](#heap-allocations)). For non-UTF-8 or ASCII input, `BufRead::read_until`, `bstr`, `linereader` skip UTF-8 validation. Read for before/after writer code.

### Logging and Debugging
Page: [`references/logging-and-debugging.md`](references/logging-and-debugging.md). Make sure that logging/debug code, and the data collection feeding it, does no work when disabled. `assert!` always runs; hot non-safety assertions can become `debug_assert!`. Short page; read for PR examples.

### Wrapper Types
Page: [`references/wrapper-types.md`](references/wrapper-types.md). Accessing `RefCell`/`Mutex` contents costs time; when values are accessed together, one wrapper around a tuple (`Arc<Mutex<(u32, u32)>>`) can beat several wrappers. Depends on access pattern; measure. Read for the example.

### Machine Code
Page: [`references/machine-code.md`](references/machine-code.md). For very hot snippets, inspect generated assembly for waste such as removable bounds checks: Compiler Explorer (godbolt) for snippets, `cargo-show-asm` for whole projects; `core::arch` exposes intrinsics/SIMD. Short page; read for tool links.

### Parallelism
Page: [`references/parallelism.md`](references/parallelism.md). Rust makes safe parallelism practical, but the book only points to resources: `rayon` and `crossbeam` for threads, *Rust Atomics and Locks*, and an overview of SIMD in Rust (Nov 2025). Read for the links.

### General Tips
Page: [`references/general-tips.md`](references/general-tips.md). Language-independent principles: optimize only hot code; algorithm/data-structure changes beat micro-optimizations; minimize cache misses and branch mispredictions; many small speedups add up; use several profilers; speed up a hot function or call it less; remove silly slowdowns before clever tricks; compute lazily; check cheap common cases first (especially collections of 0, 1 or 2 elements); compact representation for common values with a fallback table; handle the most frequent cases first (measure frequencies); put a small cache in front of high-locality lookups; comment non-obvious optimized code with the profiling data that justifies it. Read for the full list and PR examples.

### Compile Times
Page: [`references/compile-times.md`](references/compile-times.md). Code-side compile-time fixes (config-side ones live in [Build Configuration](#build-configuration)). Diagnose with `cargo build --timings` (crate graph parallelism; split large serializing crates), `-Zmacro-stats` + `cargo-expand` (macros generating code comparable to hand-written code: remove or slim them), `cargo llvm-lines` (generic functions instantiated many times). Fixes for IR bloat: make generics smaller, move the non-generic part into an inner non-generic function (as in `std::fs::read`), replace `Option::map`/`Result::map_err` with `match`. Often also shrinks binary size. Read for the inner-function pattern and macro examples.
