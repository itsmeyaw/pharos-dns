//! Authoritative Zones served from Google Cloud DNS managed zones.

// The Plugin wiring (setup, refresh task, serving) lands in the next change; chunk B removes this allowance.
#![allow(dead_code, unused_imports)]

mod api;
mod auth;
mod http;
#[cfg(test)]
mod stub;
