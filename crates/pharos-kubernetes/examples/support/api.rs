use std::convert::Infallible;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{Request, Response, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

pub type Body = BoxBody<Bytes, Infallible>;

pub fn full(body: impl Into<Bytes>) -> Body {
    Full::new(body.into()).boxed()
}

pub async fn serve(
    listener: TcpListener,
    response: fn(&str, Option<&str>) -> Response<Body>,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => { result?; break; }
            result = listener.accept() => {
                let (socket, _) = result?;
                tokio::spawn(async move {
                    let service = service_fn(move |request: Request<Incoming>| async move {
                        eprintln!("{} {}", request.method(), request.uri());
                        Ok::<_, Infallible>(response(request.uri().path(), request.uri().query()))
                    });
                    let _ = http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
                });
            }
        }
    }
    Ok(())
}
