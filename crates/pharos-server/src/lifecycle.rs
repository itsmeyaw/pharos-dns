use std::{future::Future, io, pin::Pin};

type Hook = Box<dyn Fn() -> Pin<Box<dyn Future<Output = io::Result<()>> + Send>> + Send + Sync>;

/// Hook phase. OnStartup maps to Startup, OnRestart to Reload, and
/// OnFinalShutdown to Shutdown. OnShutdown hooks needed for both reload and
/// final shutdown must be registered for both; reload orchestration invokes
/// Startup again after replacing the configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Startup,
    Shutdown,
    Reload,
}

/// Setup-time registration of ordered synchronous or asynchronous hooks.
#[derive(Default)]
pub struct Lifecycle {
    hooks: Vec<(Phase, Hook)>,
}

impl Lifecycle {
    pub fn register<F, Fut>(&mut self, phase: Phase, hook: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<()>> + Send + 'static,
    {
        self.hooks.push((phase, Box::new(move || Box::pin(hook()))));
    }

    pub fn register_sync<F>(&mut self, phase: Phase, hook: F)
    where
        F: Fn() -> io::Result<()> + Send + Sync + 'static,
    {
        self.register(phase, move || std::future::ready(hook()));
    }

    pub async fn run(&self, phase: Phase) -> io::Result<()> {
        for (_, hook) in self
            .hooks
            .iter()
            .filter(|(registered, _)| *registered == phase)
        {
            hook().await?;
        }
        Ok(())
    }
}
