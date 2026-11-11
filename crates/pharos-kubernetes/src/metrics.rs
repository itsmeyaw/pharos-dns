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
const MAX_WAIT: Duration = Duration::from_secs(100 * 365 * 24 * 60 * 60);

#[derive(Clone)]
pub struct Layer {
    metrics: KubernetesMetrics,
    host: String,
    limiter: Arc<Mutex<Limiter>>,
    inflight: Option<Arc<tokio::sync::Semaphore>>,
}

struct Limiter {
    tokens: f64,
    updated: Instant,
    rate: f64,
    burst: f64,
}

impl Limiter {
    fn reserve(&mut self, now: Instant) -> Duration {
        let base = now.max(self.updated);
        self.tokens = (self.tokens
            + now.saturating_duration_since(self.updated).as_secs_f64() * self.rate)
            .min(self.burst);
        let delay = if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Duration::ZERO
        } else {
            // shortcut: waits cap at 100 years; use an unbounded scheduler for slower rates.
            let delay = Duration::from_secs_f64(
                ((1.0 - self.tokens) / self.rate).min(MAX_WAIT.as_secs_f64()),
            );
            self.tokens = 0.0;
            (base - now).saturating_add(delay).min(MAX_WAIT)
        };
        self.updated = now.checked_add(delay).unwrap_or(now);
        delay
    }
}

impl Layer {
    pub fn new(
        metrics: KubernetesMetrics,
        host: String,
        qps: f32,
        burst: usize,
        max_inflight: usize,
    ) -> Self {
        let rate = if qps == 0.0 {
            REQUESTS_PER_SECOND
        } else {
            f64::from(qps)
        };
        let burst = if burst == 0 { BURST } else { burst as f64 };
        Self {
            metrics,
            host,
            limiter: Arc::new(Mutex::new(Limiter {
                tokens: burst,
                updated: Instant::now(),
                rate,
                burst,
            })),
            inflight: (max_inflight != 0)
                .then(|| Arc::new(tokio::sync::Semaphore::new(max_inflight))),
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
        let watch = request
            .uri()
            .query()
            .is_some_and(|query| query.split('&').any(|part| part == "watch=true"));
        let metric = self
            .layer
            .metrics
            .request(request.method().as_str(), &self.layer.host);
        let start = Instant::now();
        let delay = if watch {
            Duration::ZERO
        } else {
            self.layer.limiter.lock().unwrap().reserve(Instant::now())
        };
        let future = self.inner.call(request);
        let inflight = self.layer.inflight.clone();
        Box::pin(async move {
            if !watch {
                let throttled = Instant::now();
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                metric.rate_limiter(throttled.elapsed().as_secs_f64());
            }
            let _permit = match inflight {
                Some(semaphore) => Some(
                    semaphore
                        .acquire_owned()
                        .await
                        .expect("semaphore is never closed"),
                ),
                None => None,
            };
            let response = future.await;
            let code = response.as_ref().map(|response| response.status());
            let code = code.as_ref().map_or("<error>", http::StatusCode::as_str);
            if watch {
                metric.result(code);
            } else {
                metric.observe(start.elapsed().as_secs_f64(), code);
            }
            response
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Duration, Instant, Limiter, MAX_WAIT};

    #[test]
    fn configured_rate_and_burst_reserve_slots_in_order() {
        let now = Instant::now();
        let mut limiter = Limiter {
            tokens: 1.0,
            updated: now,
            rate: 100.0,
            burst: 1.0,
        };
        assert_eq!(limiter.reserve(now), Duration::ZERO);
        assert_eq!(limiter.reserve(now), Duration::from_millis(10));
        assert_eq!(limiter.reserve(now), Duration::from_millis(20));
        assert_eq!(
            limiter.reserve(now + Duration::from_millis(30)),
            Duration::ZERO
        );
    }

    #[test]
    fn extremely_small_rate_does_not_overflow() {
        let now = Instant::now();
        let mut limiter = Limiter {
            tokens: 0.0,
            updated: now,
            rate: f64::MIN_POSITIVE,
            burst: 1.0,
        };
        assert_eq!(limiter.reserve(now), MAX_WAIT);
    }
}
