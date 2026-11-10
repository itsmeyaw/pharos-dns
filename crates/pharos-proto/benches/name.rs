use criterion::{Criterion, criterion_group, criterion_main};
use pharos_proto::NameRef;
use std::hint::black_box;

fn name_benchmarks(criterion: &mut Criterion) {
    let wire = b"\x03www\x07example\x03com\0";
    let other_wire = b"\x03WWW\x07EXAMPLE\x03COM\0";
    let name = NameRef::parse(wire, 0).unwrap();
    let other = NameRef::parse(other_wire, 0).unwrap();

    criterion.bench_function("name/wire_parse", |bencher| {
        bencher.iter(|| NameRef::parse(black_box(wire), 0).unwrap())
    });
    criterion.bench_function("name/compare", |bencher| {
        bencher.iter(|| black_box(name) == black_box(other))
    });
}

criterion_group!(benches, name_benchmarks);
criterion_main!(benches);
