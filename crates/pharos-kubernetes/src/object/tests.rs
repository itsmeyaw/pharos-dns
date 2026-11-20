use super::{Endpoints, Port, Service};
use k8s_openapi::api::{core::v1, discovery::v1::EndpointSlice};
use serde_json::json;

#[test]
fn only_named_non_nil_ports_create_srv_records() {
    assert!(
        Port {
            name: "http".into(),
            protocol: "TCP".into(),
            port: 80,
        }
        .has_srv()
    );
    assert!(
        !Port {
            name: String::new(),
            protocol: "TCP".into(),
            port: 80,
        }
        .has_srv()
    );
    assert!(
        !Port {
            name: "http".into(),
            protocol: "TCP".into(),
            port: -1,
        }
        .has_srv()
    );
}

#[test]
fn service_annotation_enables_unready_endpoint_answers() {
    let service = Service::from(
        serde_json::from_value::<v1::Service>(json!({
            "metadata": {
                "annotations": {
                    "service.alpha.kubernetes.io/tolerate-unready-endpoints": "true"
                }
            }
        }))
        .unwrap(),
    );
    assert!(service.tolerate_unready_endpoints);
}

#[test]
fn slice_retains_unready_endpoints_for_service_policy() {
    let endpoints = Endpoints::from(
        serde_json::from_value::<EndpointSlice>(json!({
            "addressType": "IPv4",
            "endpoints": [{
                "addresses": ["192.0.2.1"],
                "conditions": {"ready": false}
            }]
        }))
        .unwrap(),
    );
    assert_eq!(endpoints.addresses.len(), 1);
    assert!(!endpoints.addresses[0].ready);
}
