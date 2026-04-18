use ghost_proxy::{validate_config, ProxyConfig, ProxyEntry};

#[test]
fn test_valid_config() {
    let config = ProxyConfig {
        proxies: vec![ProxyEntry {
            stable_port: 2222,
            base_port: 3000,
            range: 1000,
            secret: "IFEWGR3EEB2GQ3LTOB2GQ3LTON2GQ3LT".to_string(), // Valid Base32
        }],
    };
    assert!(validate_config(&config).is_ok());
}

#[test]
fn test_invalid_port_range() {
    let config = ProxyConfig {
        proxies: vec![ProxyEntry {
            stable_port: 2222,
            base_port: 65000,
            range: 1000, // 65000 + 1000 > 65535
            secret: "IFEWGR3EEB2GQ3LTOB2GQ3LTON2GQ3LT".to_string(),
        }],
    };
    let res = validate_config(&config);
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("exceeds 65535"));
}

#[test]
fn test_collision() {
    let config = ProxyConfig {
        proxies: vec![ProxyEntry {
            stable_port: 3500, // Inside range 3000-4000
            base_port: 3000,
            range: 1000,
            secret: "IFEWGR3EEB2GQ3LTOB2GQ3LTON2GQ3LT".to_string(),
        }],
    };
    let res = validate_config(&config);
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("Collision detected"));
}

#[test]
fn test_invalid_secret() {
    let config = ProxyConfig {
        proxies: vec![ProxyEntry {
            stable_port: 2222,
            base_port: 3000,
            range: 1000,
            secret: "INVALID_SECRET!@#".to_string(),
        }],
    };
    let res = validate_config(&config);
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("not a valid Base32 string"));
}

#[test]
fn test_empty_secret() {
    let config = ProxyConfig {
        proxies: vec![ProxyEntry {
            stable_port: 2222,
            base_port: 3000,
            range: 1000,
            secret: "".to_string(),
        }],
    };
    let res = validate_config(&config);
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("cannot be empty"));
}
