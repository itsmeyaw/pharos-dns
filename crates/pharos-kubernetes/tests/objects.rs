use k8s_openapi::api::{core::v1, discovery::v1::EndpointSlice};
use pharos_kubernetes::object::{Endpoints, Pod, Service};
use serde_json::json;

#[test]
fn service_keeps_addresses_and_supplies_port_sentinel() {
    let input: v1::Service = serde_json::from_value(json!({
        "metadata": {"name":"web", "namespace":"prod", "resourceVersion":"9"},
        "spec": {"clusterIP":"None", "externalIPs":["10.0.0.3"]},
        "status": {"loadBalancer":{"ingress":[{"hostname":"lb.example"}]}}
    }))
    .unwrap();
    let service = Service::from(input);
    assert!(service.headless());
    assert_eq!(service.cluster_ips, ["None"]);
    assert_eq!(service.external_ips, ["10.0.0.3", "lb.example"]);
    assert_eq!(service.ports[0].port, -1);
}

#[test]
fn endpoints_exclude_unready_and_retain_names() {
    let input: EndpointSlice = serde_json::from_value(json!({
        "metadata":{"name":"slice", "namespace":"prod", "labels":{"kubernetes.io/service-name":"web"}},
        "addressType":"IPv4",
        "endpoints":[
            {"addresses":["10.0.0.1"], "hostname":"host", "nodeName":"node", "targetRef":{"name":"pod"}},
            {"addresses":["10.0.0.2"], "conditions":{"ready":false}},
            {"addresses":["10.0.0.3"], "conditions":{"ready":true}}
        ]
    })).unwrap();
    let ep = Endpoints::from(input);
    assert_eq!(ep.service_name.as_ref(), "web");
    assert_eq!(ep.addresses.len(), 2);
    assert_eq!(ep.addresses[0].hostname, "host");
    assert_eq!(ep.addresses[0].node_name, "node");
    assert_eq!(ep.addresses[0].target_ref_name, "pod");
    assert_eq!(ep.ports[0].port, -1);
}

#[test]
fn pod_retains_all_ips_and_deletion_status() {
    let input: v1::Pod = serde_json::from_value(json!({
        "metadata":{"name":"pod", "namespace":"prod", "deletionTimestamp":"2024-01-01T00:00:00Z"},
        "status":{"podIPs":[{"ip":"10.0.0.1"},{"ip":"fd00::1"}]}
    }))
    .unwrap();
    let pod = Pod::from(input);
    assert_eq!(pod.ips, ["10.0.0.1", "fd00::1"]);
    assert!(pod.deleting);
}

#[test]
fn endpoint_slice_ignores_unsupported_address_types() {
    let input: EndpointSlice = serde_json::from_value(json!({
        "metadata":{"name":"slice", "namespace":"prod"},
        "addressType":"FQDN",
        "endpoints":[{"addresses":["example.org"]}]
    }))
    .unwrap();
    assert!(Endpoints::from(input).addresses.is_empty());
}

#[test]
fn endpoint_zones_are_optional_and_only_retain_ready_addresses() {
    let input: EndpointSlice = serde_json::from_value(json!({
        "metadata":{"name":"slice", "namespace":"prod"},
        "addressType":"IPv4",
        "endpoints":[
            {"addresses":["10.0.0.1", "10.0.0.2"], "zone":"US-West-2A"},
            {"addresses":["10.0.0.3"], "zone":"us-west-2b", "conditions":{"ready":false}},
            {"addresses":["10.0.0.4"]},
            {"addresses":["10.0.0.5"], "zone":"", "conditions":{"ready":true}},
            {"addresses":["10.0.0.1"], "zone":"US-West-2B"},
            {"addresses":["10.0.0.2"]}
        ]
    }))
    .unwrap();
    assert!(Endpoints::from(input.clone()).zones.is_none());
    let ep = Endpoints::from_slice_with_zones(input);
    let zones = ep.zones.as_ref().unwrap();
    assert_eq!(zones.len(), 3);
    assert_eq!(zones.get("10.0.0.1").unwrap(), "us-west-2b");
    assert_eq!(zones.get("10.0.0.2").unwrap(), "us-west-2a");
    assert_eq!(zones.get("10.0.0.5").unwrap(), "");
    assert!(!zones.contains_key("10.0.0.3"));
    assert!(!zones.contains_key("10.0.0.4"));
    assert_eq!(ep.clone().zones, ep.zones);
    let mut changed = ep.clone();
    changed
        .zones
        .as_mut()
        .unwrap()
        .insert("10.0.0.1".into(), "other".into());
    assert_ne!(changed, ep);

    let no_zone: EndpointSlice = serde_json::from_value(json!({
        "addressType":"IPv6", "endpoints":[{"addresses":["fd00::1"]}]
    }))
    .unwrap();
    assert!(Endpoints::from_slice_with_zones(no_zone).zones.is_none());
    let ipv6: EndpointSlice = serde_json::from_value(json!({
        "addressType":"IPv6", "endpoints":[{"addresses":["fd00::1"], "zone":"West"}]
    }))
    .unwrap();
    assert_eq!(
        Endpoints::from_slice_with_zones(ipv6)
            .zones
            .unwrap()
            .get("fd00::1")
            .unwrap(),
        "west"
    );
    let unsupported: EndpointSlice = serde_json::from_value(json!({
        "addressType":"FQDN", "endpoints":[{"addresses":["example.org"], "zone":"west"}]
    }))
    .unwrap();
    assert!(
        Endpoints::from_slice_with_zones(unsupported)
            .zones
            .is_none()
    );
}
