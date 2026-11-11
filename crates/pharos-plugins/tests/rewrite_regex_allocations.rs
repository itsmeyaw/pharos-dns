#![forbid(unsafe_code)]
#![cfg(feature = "plugin-rewrite")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, Section, Type};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use std::{
    alloc::System,
    future::Future,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::{Context as TaskContext, Poll, Waker},
};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

struct Answer;
impl Next for Answer {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        builder.question(q.name, q.qtype, q.qclass).unwrap();
        builder
            .record(
                Section::Answer,
                q.name,
                Type::A,
                Class::IN,
                5,
                &[127, 0, 0, 1],
            )
            .unwrap();
        let _ = builder.finish();
        Outcome::Response
    }
}
struct Done<'a>(&'a AtomicUsize);
impl Drop for Done<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Release);
    }
}

#[test]
fn cold_regex_matching_stays_allocation_free_across_threads() {
    let config = r".:53 {
 rewrite continue name regex ^(.*)\.other\.$ {1}.internal.
 rewrite ttl regex ^((a|b|c|d)?)+\.example\.$ 30
}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let plugin = chain.rewrite.as_ref().unwrap();
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x03bbb\x07example\0\0\x01\0\x01";
    let query = Message::parse(wire).unwrap();
    let root: Name = ".".parse().unwrap();
    let client = "127.0.0.1:1234".parse().unwrap();
    let local = "127.0.0.1:53".parse().unwrap();
    let ready = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let start = AtomicBool::new(false);
    let release = AtomicBool::new(false);
    std::thread::scope(|scope| {
        for _ in 0..2 {
            let (ready, done, start, release, root) = (&ready, &done, &start, &release, &root);
            scope.spawn(move || {
                let mut response = Vec::with_capacity(512);
                let mut slots = [];
                let mut cx = Context {
                    query,
                    client,
                    local,
                    transport: Transport::Dns,
                    protocol: Protocol::Udp,
                    domain: root,
                    metadata: Metadata::new(&mut slots),
                    response: &mut response,
                    max_response_size: 512,
                };
                ready.fetch_add(1, Ordering::Release);
                while !start.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                let done_guard = Done(done);
                let future = plugin.serve(&mut cx, Answer);
                let mut future = std::pin::pin!(future);
                let outcome = future
                    .as_mut()
                    .poll(&mut TaskContext::from_waker(Waker::noop()));
                drop(done_guard);
                while !release.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                assert_eq!(outcome, Poll::Ready(Outcome::Response));
            });
        }
        while ready.load(Ordering::Acquire) != 2 {
            std::thread::yield_now();
        }
        let region = Region::new(GLOBAL);
        start.store(true, Ordering::Release);
        while done.load(Ordering::Acquire) != 2 {
            std::thread::yield_now();
        }
        let stats = region.change();
        release.store(true, Ordering::Release);
        assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    });
}
