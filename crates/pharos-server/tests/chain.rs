#![forbid(unsafe_code)]

use pharos_proto::{Message, MessageMut, Name};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};
use std::{
    future::Future,
    task::{Context as TaskContext, Poll, Waker},
};

struct Middleware;
struct Terminal;
struct Chain {
    middleware: Middleware,
    terminal: Terminal,
}
struct NextTerminal<'a>(&'a Chain);
struct End;

impl Plugin for Middleware {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_>, next: N) -> Outcome {
        let outcome = next.run(cx).await;
        if outcome == Outcome::Response {
            let message = Message::parse(cx.response).unwrap();
            let flags = message.flags() | 0x0400;
            MessageMut::parse(cx.response).unwrap().set_flags(flags);
        }
        outcome
    }
}
impl Plugin for Terminal {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_>, _next: N) -> Outcome {
        cx.response.extend_from_slice(&[0; 12]);
        Outcome::Response
    }
}
impl Next for NextTerminal<'_> {
    async fn run(self, cx: &mut Context<'_>) -> Outcome {
        self.0.terminal.serve(cx, End).await
    }
}
impl Next for End {
    async fn run(self, _: &mut Context<'_>) -> Outcome {
        Outcome::Error(pharos_server::Error::NoNextPlugin)
    }
}
impl Chain {
    async fn serve(&self, cx: &mut Context<'_>) -> Outcome {
        self.middleware.serve(cx, NextTerminal(self)).await
    }
}

#[test]
fn middleware_awaits_next_and_alters_its_response() {
    fn assert_send<T: Send>(_: &T) {}
    let chain = Chain {
        middleware: Middleware,
        terminal: Terminal,
    };
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&[0; 12]).unwrap(),
        client: "127.0.0.1:53".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_send(&cx);
    {
        let future = chain.serve(&mut cx);
        assert_send(&future);
        let mut future = std::pin::pin!(future);
        assert_eq!(
            future
                .as_mut()
                .poll(&mut TaskContext::from_waker(Waker::noop())),
            Poll::Ready(Outcome::Response)
        );
    }
    assert!(Message::parse(&response).unwrap().aa());
}
