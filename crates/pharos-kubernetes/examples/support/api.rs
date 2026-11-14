use std::convert::Infallible;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{
    Request, Response, StatusCode, body::Incoming, header::HeaderValue, server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

pub type Body = BoxBody<Bytes, Infallible>;

pub fn full(body: impl Into<Bytes>) -> Body {
    Full::new(body.into()).boxed()
}

pub async fn serve(
    listener: TcpListener,
    exists: fn(&str) -> bool,
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
                        let result = match request.method().as_str() {
                            "GET" => response(request.uri().path(), request.uri().query()),
                            "HEAD" => {
                                // RFC 9110 §9.3.2: HEAD shares GET status and headers without content.
                                let (parts, _) = response(request.uri().path(), request.uri().query()).into_parts();
                                Response::from_parts(parts, full(Bytes::new()))
                            }
                            "POST" | "PUT" | "DELETE" | "CONNECT" | "OPTIONS" | "TRACE" | "PATCH"
                                if exists(request.uri().path()) =>
                            {
                                // RFC 9110 §9.1: Known methods unsupported by fixtures receive 405.
                                let mut result = Response::new(full("Method Not Allowed\n"));
                                *result.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
                                result.headers_mut().insert("allow", HeaderValue::from_static("GET, HEAD"));
                                result.headers_mut().insert("content-type", HeaderValue::from_static("text/plain; charset=utf-8"));
                                result
                            }
                            "POST" | "PUT" | "DELETE" | "CONNECT" | "OPTIONS" | "TRACE" | "PATCH" => {
                                // RFC 9110 §15.5.5: Unknown fixture paths remain 404.
                                response(request.uri().path(), request.uri().query())
                            }
                            _ => {
                                // RFC 9110 §9.1: Unknown method tokens receive 501.
                                let mut result = Response::new(full("Not Implemented\n"));
                                *result.status_mut() = StatusCode::NOT_IMPLEMENTED;
                                result.headers_mut().insert("content-type", HeaderValue::from_static("text/plain; charset=utf-8"));
                                result
                            }
                        };
                        Ok::<_, Infallible>(result)
                    });
                    let _ = http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
                });
            }
        }
    }
    Ok(())
}
