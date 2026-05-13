use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::thread;

use icmp2tunnel_socks::{
    bind_listener, default_loopback_bind_addr, negotiate_no_auth, parse_request, write_reply, Command,
    SocksError, TargetAddr,
};

fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind pair listener");
    let addr = listener.local_addr().expect("pair local_addr");

    let th = thread::spawn(move || listener.accept().expect("accept pair").0);
    let client = TcpStream::connect(addr).expect("connect pair");
    let server = th.join().expect("join accept thread");
    (client, server)
}

#[test]
fn negotiates_no_auth() {
    let (mut client, mut server) = pair();

    let th = thread::spawn(move || negotiate_no_auth(&mut server));
    client.write_all(&[0x05, 0x02, 0x02, 0x00]).expect("write greeting");

    let mut reply = [0u8; 2];
    client.read_exact(&mut reply).expect("read method reply");
    assert_eq!(reply, [0x05, 0x00]);
    assert!(th.join().expect("join").is_ok());
}

#[test]
fn rejects_unsupported_auth_methods() {
    let (mut client, mut server) = pair();
    let th = thread::spawn(move || negotiate_no_auth(&mut server));
    client.write_all(&[0x05, 0x01, 0x02]).expect("write greeting");

    let mut reply = [0u8; 2];
    client.read_exact(&mut reply).expect("read method reply");
    assert_eq!(reply, [0x05, 0xff]);

    let err = th.join().expect("join").expect_err("should fail");
    assert!(matches!(err, SocksError::NoAcceptableMethod));
}

#[test]
fn parses_connect_for_all_address_types() {
    for req in [
        vec![0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xbb],
        vec![0x05, 0x01, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x00, 0x50],
        {
            let mut v = vec![0x05, 0x01, 0x00, 0x04];
            v.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
            v.extend_from_slice(&1080u16.to_be_bytes());
            v
        },
    ] {
        let (mut client, mut server) = pair();
        let th = thread::spawn(move || parse_request(&mut server));
        client.write_all(&req).expect("write request");
        let parsed = th.join().expect("join").expect("parse request");
        assert_eq!(parsed.command, Command::Connect);
    }
}

#[test]
fn rejects_invalid_version() {
    let (mut client, mut server) = pair();
    let th = thread::spawn(move || parse_request(&mut server));
    client
        .write_all(&[0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
        .expect("write request");
    let err = th.join().expect("join").expect_err("must fail");
    assert!(matches!(err, SocksError::InvalidVersion(0x04)));
}

#[test]
fn writes_success_and_failure_replies() {
    let (mut client, mut server) = pair();
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

    let th = thread::spawn(move || {
        write_reply(&mut server, 0x00, bind).expect("success reply");
        write_reply(&mut server, 0x07, bind).expect("failure reply");
    });

    let mut buf = [0u8; 20];
    client.read_exact(&mut buf[..10]).expect("read success");
    assert_eq!(&buf[..4], &[0x05, 0x00, 0x00, 0x01]);
    client.read_exact(&mut buf[..10]).expect("read failure");
    assert_eq!(&buf[..4], &[0x05, 0x07, 0x00, 0x01]);
    th.join().expect("join");
}

#[test]
fn helper_binds_to_loopback_by_default() {
    let listener = bind_listener(None).expect("bind default");
    assert_eq!(listener.local_addr().expect("local_addr").ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(default_loopback_bind_addr(1234), SocketAddr::from(([127, 0, 0, 1], 1234)));
}

#[test]
fn integration_connects_to_local_echo_server() {
    let echo_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind echo");
    let echo_addr = echo_listener.local_addr().expect("echo local addr");
    let echo = thread::spawn(move || {
        let (mut conn, _) = echo_listener.accept().expect("accept echo client");
        let mut buf = [0u8; 5];
        conn.read_exact(&mut buf).expect("read echo payload");
        conn.write_all(&buf).expect("write echo payload");
    });

    let (mut client, mut server) = pair();
    let proxy = thread::spawn(move || {
        negotiate_no_auth(&mut server).expect("negotiate");
        let req = parse_request(&mut server).expect("parse request");
        assert_eq!(req.command, Command::Connect);

        let target = match req.target {
            TargetAddr::Ip(ip) => SocketAddr::new(ip, req.port),
            TargetAddr::Domain(_) => panic!("expected ip target"),
        };

        let mut upstream = TcpStream::connect(target).expect("connect upstream");
        write_reply(&mut server, 0x00, upstream.local_addr().expect("upstream local addr")).expect("write reply");

        let mut payload = [0u8; 5];
        server.read_exact(&mut payload).expect("read payload from client");
        upstream.write_all(&payload).expect("forward to echo");
        upstream.read_exact(&mut payload).expect("read from echo");
        server.write_all(&payload).expect("write back client");
    });

    client
        .write_all(&[0x05, 0x01, 0x00])
        .expect("write greeting");
    let mut method_reply = [0u8; 2];
    client.read_exact(&mut method_reply).expect("read method reply");
    assert_eq!(method_reply, [0x05, 0x00]);

    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&match echo_addr.ip() {
        IpAddr::V4(v4) => v4.octets(),
        IpAddr::V6(_) => panic!("expected v4 echo listener"),
    });
    req.extend_from_slice(&echo_addr.port().to_be_bytes());
    client.write_all(&req).expect("write connect request");

    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).expect("read connect reply");
    assert_eq!(&reply[..2], &[0x05, 0x00]);

    client.write_all(b"hello").expect("write proxy payload");
    let mut echoed = [0u8; 5];
    client.read_exact(&mut echoed).expect("read echoed payload");
    assert_eq!(&echoed, b"hello");

    proxy.join().expect("join proxy thread");
    echo.join().expect("join echo thread");
}
