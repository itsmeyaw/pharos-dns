use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use pharos_server::metrics::KubernetesMetrics;
use tower::{Layer as TowerLayer, Service};

const REQUESTS_PER_SECOND: f64 = 5.0;
const BURST: f64 = 10.0;

#[derive(Clone)]
pub struct Layer {
    metrics: KubernetesMetrics,
    host: String,
    limiter: Arc<Mutex<Limiter>>,
}

struct Limiter {
    tokens: f64,
    updated: Instant,
}

impl Limiter {
    fn reserve(&mut self) -> Duration {
        let now = Instant::now();
        let base = now.max(self.updated);
        self.tokens = (self.tokens
            + now.saturating_duration_since(self.updated).as_secs_f64() * REQUESTS_PER_SECOND)
            .min(BURST);
        let delay = if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Duration::ZERO
        } else {
            let delay = Duration::from_secs_f64((1.0 - self.tokens) / REQUESTS_PER_SECOND);
            self.tokens = 0.0;
            (base - now) + delay
        };
        self.updated = now + delay;
        delay
    }
}

impl Layer {
    pub fn new(metrics: KubernetesMetrics, host: String) -> Self {
        Self {
            metrics,
            host,
            limiter: Arc::new(Mutex::new(Limiter {
                tokens: BURST,
                updated: Instant::now(),
            })),
        }
    }
}

impl<S> TowerLayer<S> for Layer {
    type Service = Instrumented<S>;
    fn layer(&self, inner: S) -> Self::Service {
        Instrumented {
            inner,
            layer: self.clone(),
        }
    }
}

#[derive(Clone)]
pub struct Instrumented<S> {
    inner: S,
    layer: Layer,
}

impl<S, B> Service<http::Request<kube::client::Body>> for Instrumented<S>
where
    S: Service<http::Request<kube::client::Body>, Response = http::Response<B>>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    B: Send + 'static,
{
    type Response = http::Response<B>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<kube::client::Body>) -> Self::Future {
        let metric = self
            .layer
            .metrics
            .request(request.method().as_str(), &self.layer.host);
        let start = Instant::now();
        let delay = self.layer.limiter.lock().unwrap().reserve();
        let future = self.inner.call(request);
        Box::pin(async move {
            if !delay.is_zero() {
                let throttled = Instant::now();
                tokio::time::sleep(delay).await;
                metric.rate_limiter(throttled.elapsed().as_secs_f64());
            }
            let response = future.await;
            match &response {
                Ok(response) => {
                    metric.observe(start.elapsed().as_secs_f64(), response.status().as_str())
                }
                Err(_) => metric.observe(start.elapsed().as_secs_f64(), "<error>"),
            }
            response
        })
    }
}
