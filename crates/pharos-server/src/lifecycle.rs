use std::{future::Future, io, pin::Pin, sync::Arc};

type Hook = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = io::Result<()>> + Send>> + Send + Sync>;

/// Hook phases in the configuration lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Startup,
    /// Listeners have been installed after Startup, including on Reload.
    Started,
    Shutdown,
    Restart,
    RestartFailed,
}

/// Setup-time registration of ordered synchronous or asynchronous hooks.
#[derive(Clone, Default)]
pub struct Lifecycle {
    hooks: Vec<(Phase, Hook)>,
}

impl Lifecycle {
    pub fn register<F, Fut>(&mut self, phase: Phase, hook: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<()>> + Send + 'static,
    {
        self.hooks.push((phase, Arc::new(move || Box::pin(hook()))));
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

    pub fn extend(&mut self, other: &Self) {
        self.hooks.extend(other.hooks.iter().cloned());
    }
}

impl std::fmt::Debug for Lifecycle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lifecycle")
            .field("hooks", &self.hooks.len())
            .finish()
    }
}
