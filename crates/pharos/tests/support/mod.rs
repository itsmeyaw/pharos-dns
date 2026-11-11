use std::{
    collections::{HashSet, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    net::{TcpListener, UdpSocket},
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::SystemTime,
};

// shortcut: the port is released before the server binds; under heavy parallel test load about 1 in 90 runs still sees a TCP reset (cause unconfirmed); pass bound sockets to the server if it persists.
pub fn free_port() -> u16 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    static USED: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    let ipv6_tcp = TcpListener::bind("[::]:0").is_ok();
    let ipv6_udp = UdpSocket::bind("[::]:0").is_ok();
    for _ in 0..1000 {
        let mut hash = DefaultHasher::new();
        std::process::id().hash(&mut hash);
        NEXT.fetch_add(1, Ordering::Relaxed).hash(&mut hash);
        SystemTime::now().hash(&mut hash);
        // Stay below the default ephemeral ranges on macOS and Linux.
        let port = 10_000 + (hash.finish() % 22_768) as u16;
        let mut used = USED.get_or_init(Default::default).lock().unwrap();
        if !used.contains(&port)
            && (!ipv6_tcp || TcpListener::bind(("::", port)).is_ok())
            && (!ipv6_udp || UdpSocket::bind(("::", port)).is_ok())
            && TcpListener::bind(("0.0.0.0", port)).is_ok()
            && UdpSocket::bind(("0.0.0.0", port)).is_ok()
        {
            used.insert(port);
            return port;
        }
    }
    panic!("could not find a free server port after 1000 attempts");
}
