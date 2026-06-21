//! Sparse Merkle tree operation benchmarks.
#![allow(missing_docs)]

use alloy_eip8289::SparseMerkleTree;
use alloy_primitives::{B256, U256};
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

const TREE_SIZES: [usize; 3] = [1, 64, 1024];

fn key(index: usize) -> B256 {
    B256::from(U256::from(index).to_be_bytes::<32>())
}

fn value(index: usize) -> B256 {
    B256::from(U256::from(index + 1).to_be_bytes::<32>())
}

fn populated_tree(size: usize) -> SparseMerkleTree {
    let mut tree = SparseMerkleTree::new();
    for index in 0..size {
        tree.update(key(index), value(index));
    }
    tree
}

fn bench_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("smt_update");
    group.throughput(Throughput::Elements(1));

    for size in TREE_SIZES {
        let tree = populated_tree(size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter_batched(
                || tree.clone(),
                |mut tree| tree.update(key(size), value(size)),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("smt_prove");
    group.throughput(Throughput::Elements(1));

    for size in TREE_SIZES {
        let tree = populated_tree(size);
        let target = key(size - 1);
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| tree.prove(target));
        });
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("smt_verify");
    group.throughput(Throughput::Elements(1));

    for size in TREE_SIZES {
        let tree = populated_tree(size);
        let target = key(size - 1);
        let proof = tree.prove(target);
        let root = tree.root();
        let target_value = value(size - 1);
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| proof.verify(target, target_value, root));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_update, bench_prove, bench_verify);
criterion_main!(benches);
