//! Authoritative Zones served from Google Cloud DNS managed zones.

// The Plugin wiring (setup, refresh task, serving) lands in the next change; chunk B removes this allowance.
#![cfg_attr(not(test), allow(dead_code))]

mod http;
#[cfg(test)]
mod stub;
