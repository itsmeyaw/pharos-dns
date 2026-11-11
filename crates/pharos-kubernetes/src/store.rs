#[cfg(test)]
mod tests {
    use super::Store;
    use crate::object::{Endpoints, Namespace, Pod, Service};
    use k8s_openapi::api::{core::v1, discovery::v1::EndpointSlice};
    use serde_json::json;

    #[test]
    fn multicluster_indices_track_updates_deletes_and_relists() {
        let store = Store::default();
        let import = |version: &str, ip: &str| {
            crate::object::ServiceImport::from(
                serde_json::from_value::<kube::core::DynamicObject>(json!({
                    "apiVersion":"multicluster.x-k8s.io/v1alpha1", "kind":"ServiceImport",
                    "metadata":{"name":"web", "namespace":"prod", "resourceVersion":version},
                    "spec":{"type":"ClusterSetIP", "ips":[ip]}
                }))
                .unwrap(),
            )
        };
        let slice = |name: &str, service: &str, cluster: &str| {
            crate::object::MultiClusterEndpoints::from(
                serde_json::from_value::<EndpointSlice>(json!({
                    "metadata":{"name":name,"namespace":"prod","labels":{
                        "multicluster.kubernetes.io/service-name":service,
                        "multicluster.kubernetes.io/source-cluster":cluster}},
                    "addressType":"IPv4","endpoints":[{"addresses":["10.0.1.1"]}]
                }))
                .unwrap(),
            )
        };
        store.apply_service_import(import("1", "10.0.0.1"));
        store.apply_multicluster_endpoints(slice("one", "web", "east"));
        store.apply_multicluster_endpoints(slice("two", "web", "west"));
        store.with_read(|index| {
            assert_eq!(
                index.service_import("prod", "web").unwrap().cluster_ips,
                ["10.0.0.1"]
            );
            assert_eq!(index.multicluster_endpoints("prod", "web").count(), 2);
        });
        store.apply_service_import(import("2", "10.0.0.2"));
        store.apply_multicluster_endpoints(slice("one", "other", "east"));
        store.with_read(|index| {
            assert_eq!(
                index.service_import("prod", "web").unwrap().cluster_ips,
                ["10.0.0.2"]
            );
            assert_eq!(index.multicluster_endpoints("prod", "web").count(), 1);
            assert_eq!(
                index
                    .multicluster_endpoints("prod", "other")
                    .next()
                    .unwrap()
                    .cluster_id,
                "east"
            );
        });
        store.delete_multicluster_endpoints("prod", "two");
        store.replace_multicluster_endpoints(Vec::new());
        store.replace_service_imports(Vec::new());
        store.with_read(|index| {
            assert!(index.service_import("prod", "web").is_none());
            assert_eq!(index.multicluster_endpoints("prod", "web").count(), 0);
            assert_eq!(index.multicluster_endpoints("prod", "other").count(), 0);
        });
    }

    #[test]
    fn multicluster_serial_changes_on_dns_relevant_updates_only() {
        let store = Store::default();
        let mut import = crate::object::ServiceImport::from(serde_json::from_value::<kube::core::DynamicObject>(json!({
            "apiVersion":"multicluster.x-k8s.io/v1alpha1", "kind":"ServiceImport",
            "metadata":{"name":"web", "namespace":"prod", "resourceVersion":"1"},
            "spec":{"type":"ClusterSetIP", "ips":["10.0.0.1"], "ports":[{"name":"http","protocol":"TCP","port":80}]}
        })).unwrap());
        store.apply_service_import(import.clone());
        store.0.write().unwrap().multicluster_serial = 1;
        import.version = "2".into();
        import.cluster_ips = vec!["10.0.0.2".into()];
        store.apply_service_import(import.clone());
        assert_eq!(store.with_read(|i| i.multicluster_serial()), 1);
        import.version = "3".into();
        import.ports[0].port = 81;
        store.apply_service_import(import);
        assert_ne!(store.with_read(|i| i.multicluster_serial()), 1);
    }

    fn service(ip: &str) -> Service {
        Service::from(
            serde_json::from_value::<v1::Service>(json!({
                "metadata":{"name":"web", "namespace":"prod"},
                "spec":{"clusterIPs":[ip], "externalIPs":["192.0.2.1"]}
            }))
            .unwrap(),
        )
    }

    fn slice(name: &str, ip: &str) -> Endpoints {
        Endpoints::from(serde_json::from_value::<EndpointSlice>(json!({
            "metadata":{"name":name, "namespace":"prod", "labels":{"kubernetes.io/service-name":"web"}},
            "addressType":"IPv4", "endpoints":[{"addresses":[ip]}]
        })).unwrap())
    }

    #[test]
    fn updates_remove_old_indices_and_keep_multiple_slices() {
        let store = Store::default();
        store.apply_service(service("10.0.0.1"));
        store.apply_endpoints(slice("one", "10.0.1.1"));
        store.apply_endpoints(slice("two", "10.0.1.2"));
        store.with_read(|index| assert_eq!(index.counts(), (1, 2, 2, 0, 0)));
        store.apply_service(service("10.0.0.2"));
        store.apply_endpoints(slice("one", "10.0.1.3"));
        store.with_read(|index| {
            assert_eq!(index.services_by_ip("10.0.0.1").count(), 0);
            assert_eq!(index.services_by_ip("10.0.0.2").count(), 1);
            assert_eq!(index.services_by_external_ip("192.0.2.1").count(), 1);
            assert_eq!(index.endpoints("prod", "web").count(), 2);
            assert_eq!(index.endpoints_by_ip("10.0.1.1").count(), 0);
            assert_eq!(index.endpoints_by_ip("10.0.1.3").count(), 1);
        });
        store.delete_endpoints("prod", "two");
        store.with_read(|index| assert_eq!(index.endpoints("prod", "web").count(), 1));
    }

    #[test]
    fn relist_removes_objects_absent_from_new_snapshot() {
        let store = Store::default();
        store.apply_service(service("10.0.0.1"));
        store.replace_services(Vec::new());
        store.with_read(|index| {
            assert!(index.service("prod", "web").is_none());
            assert_eq!(index.services_by_ip("10.0.0.1").count(), 0);
        });
    }

    #[test]
    fn pod_and_namespace_indices_follow_changes() {
        let store = Store::default();
        let pod: v1::Pod = serde_json::from_value(json!({
            "metadata":{"name":"pod", "namespace":"prod"},
            "status":{"podIPs":[{"ip":"10.0.0.1"}]}
        }))
        .unwrap();
        let namespace: v1::Namespace =
            serde_json::from_value(json!({"metadata":{"name":"prod"}})).unwrap();
        store.apply_pod(Pod::from(pod));
        store.apply_namespace(Namespace::from(namespace));
        store.with_read(|index| {
            assert_eq!(index.pods_by_ip("10.0.0.1").count(), 1);
            assert!(index.namespace("prod").is_some());
        });
        store.replace_pods(Vec::new());
        store.delete_namespace("prod");
        store.with_read(|index| {
            assert_eq!(index.pods_by_ip("10.0.0.1").count(), 0);
            assert!(index.namespace("prod").is_none());
        });
    }

    #[test]
    fn reverse_index_deduplicates_addresses_within_a_slice() {
        let store = Store::default();
        let mut slice = slice("one", "10.0.1.1");
        slice.addresses.push(slice.addresses[0].clone());
        store.apply_endpoints(slice);
        store.with_read(|index| assert_eq!(index.endpoints_by_ip("10.0.1.1").count(), 1));
    }

    #[test]
    fn serial_tracks_dns_changes_but_not_namespace_or_metadata_updates() {
        let store = Store::default();
        assert_eq!(store.with_read(|index| index.serial()), 0);
        store.apply_service(service("10.0.0.1"));
        assert_ne!(store.with_read(|index| index.serial()), 0);
        store.0.write().unwrap().serial = 1;
        let mut unchanged = service("10.0.0.1");
        unchanged.version = "updated".into();
        store.apply_service(unchanged);
        store.apply_namespace(Namespace {
            name: "prod".into(),
            version: "1".into(),
        });
        assert_eq!(store.with_read(|index| index.serial()), 1);
        let mut same_version = service("10.0.0.1");
        same_version.version = "updated".into();
        same_version.external_name = "ignored.example".into();
        store.apply_service(same_version);
        assert_eq!(store.with_read(|index| index.serial()), 1);
        let mut external_only = service("10.0.0.1");
        external_only.version = "external".into();
        external_only.external_name = "ignored.example".into();
        external_only.external_ips.push("192.0.2.2".into());
        store.apply_service(external_only);
        assert_eq!(store.with_read(|index| index.serial()), 1);
        let mut changed = service("10.0.0.1");
        changed.version = "different".into();
        changed.external_name = "other.example".into();
        store.apply_service(changed);
        assert_ne!(store.with_read(|index| index.serial()), 1);
        store.0.write().unwrap().serial = 1;
        store.replace_services(Vec::new());
        assert_ne!(store.with_read(|index| index.serial()), 1);
    }

    #[test]
    fn serial_tracks_endpoint_and_pod_changes_across_relists() {
        let store = Store::default();
        let mut endpoint = slice("one", "10.0.1.1");
        endpoint.version = "1".into();
        store.apply_endpoints(endpoint.clone());
        store.0.write().unwrap().serial = 1;
        endpoint.version = "2".into();
        endpoint.addresses[0].target_ref_name = "renamed".into();
        store.apply_endpoints(endpoint.clone());
        store.replace_endpoints(vec![endpoint.clone()], |_| ());
        assert_eq!(store.with_read(|index| index.serial()), 1);
        endpoint.version = "3".into();
        endpoint.addresses[0].hostname = "node".into();
        store.apply_endpoints(endpoint);
        assert_ne!(store.with_read(|index| index.serial()), 1);

        let mut pod = Pod {
            version: "1".into(),
            name: "pod".into(),
            namespace: "prod".into(),
            ips: vec!["10.0.0.1".into()],
            deleting: false,
        };
        store.apply_pod(pod.clone());
        store.0.write().unwrap().serial = 1;
        pod.version = "2".into();
        store.apply_pod(pod.clone());
        store.replace_pods(vec![pod.clone()]);
        assert_eq!(store.with_read(|index| index.serial()), 1);
        pod.version = "3".into();
        pod.ips.push("10.0.0.2".into());
        store.apply_pod(pod);
        assert_ne!(store.with_read(|index| index.serial()), 1);
        store.0.write().unwrap().serial = 1;
        store.replace_pods(Vec::new());
        assert_ne!(store.with_read(|index| index.serial()), 1);
    }

    #[test]
    fn serial_tracks_zone_only_endpoint_changes() {
        let store = Store::default();
        let mut endpoint = slice("one", "10.0.1.1");
        endpoint.version = "1".into();
        endpoint.zones = Some(Box::new(
            [(String::from("10.0.1.1"), String::from("zone-a"))].into(),
        ));
        store.apply_endpoints(endpoint.clone());
        store.0.write().unwrap().serial = 1;
        endpoint.version = "2".into();
        endpoint
            .zones
            .as_mut()
            .unwrap()
            .insert("10.0.1.1".into(), "zone-b".into());
        store.apply_endpoints(endpoint.clone());
        assert_ne!(store.with_read(|index| index.serial()), 1);
        store.0.write().unwrap().serial = 1;
        endpoint.version = "3".into();
        endpoint
            .zones
            .as_mut()
            .unwrap()
            .insert("10.0.1.1".into(), "zone-c".into());
        store.replace_endpoints(vec![endpoint], |_| ());
        assert_ne!(store.with_read(|index| index.serial()), 1);
    }

    #[test]
    fn terminating_pod_relist_keeps_previous_record_until_delete() {
        let store = Store::default();
        let pod = Pod {
            version: "1".into(),
            name: "pod".into(),
            namespace: "prod".into(),
            ips: vec!["10.0.0.1".into()],
            deleting: false,
        };
        store.apply_pod(pod.clone());
        store.0.write().unwrap().serial = 1;
        let mut terminating = pod;
        terminating.version = "2".into();
        terminating.deleting = true;
        store.replace_pods(vec![terminating]);
        store.with_read(|index| {
            assert_eq!(index.pods_by_ip("10.0.0.1").count(), 1);
            assert_eq!(index.serial(), 1);
        });
        store.replace_pods(Vec::new());
        store.with_read(|index| {
            assert_eq!(index.pods_by_ip("10.0.0.1").count(), 0);
            assert_ne!(index.serial(), 1);
        });
    }

    // CoreDNS controller_test.go TestServiceModified; external-zone flags belong to k8s_external.
    #[test]
    fn coredns_service_modified_internal_rows() {
        let mut base = service("10.0.0.1");
        base.version = "1".into();
        let mut same = base.clone();
        same.version = "2".into();
        let mut external_ip = same.clone();
        external_ip.external_ips = vec!["192.0.2.2".into()];
        let mut external_name = same.clone();
        external_name.external_name = "target.example".into();
        let mut port_name = same.clone();
        port_name.ports[0].name = "other".into();
        let mut extra_port = port_name.clone();
        extra_port.ports.push(port_name.ports[0].clone());
        for (name, old, new, expected) in [
            ("add", None, &same, true),
            ("add with external IP", None, &external_ip, true),
            ("same", Some(&base), &same, false),
            ("external IP", Some(&base), &external_ip, false),
            ("external name", Some(&base), &external_name, true),
            ("port name", Some(&base), &port_name, true),
            ("port count", Some(&base), &extra_port, true),
        ] {
            assert_eq!(super::service_changed(old, new), expected, "{name}");
        }
    }

    // CoreDNS controller_test.go TestPodModified.
    #[test]
    fn coredns_pod_modified_rows() {
        for (old, new, changed) in [
            (&["10.240.0.1"][..], &["10.240.0.1"][..], false),
            (&[][..], &["10.240.0.1"][..], true),
            (&["10.240.0.1"][..], &["10.240.0.2"][..], true),
            (
                &["10.240.0.1", "fd00::1"][..],
                &["10.240.0.1", "fd00::1"][..],
                false,
            ),
        ] {
            let pod = |version: &str, ips: &[&str]| Pod {
                version: version.into(),
                name: "dns-test".into(),
                namespace: "testns".into(),
                ips: ips.iter().map(|ip| (*ip).to_owned()).collect(),
                deleting: false,
            };
            assert_eq!(
                super::pod_changed(Some(&pod("1", old)), &pod("2", new)),
                changed
            );
        }
    }
}
// Incremental indices shared by watchers and DNS readers.

use crate::object::{Endpoints, MultiClusterEndpoints, Namespace, Pod, Service, ServiceImport};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};

type Names<T> = HashMap<Arc<str>, HashMap<Arc<str>, Arc<T>>>;
type Reverse<T> = HashMap<Arc<str>, Vec<Arc<T>>>;
type Grouped<T> = HashMap<Arc<str>, Reverse<T>>;

#[derive(Default)]
pub struct Index {
    serial: u32,
    multicluster_serial: u32,
    allowed_namespaces: HashSet<Arc<str>>,
    require_namespace: bool,
    services: Names<Service>,
    service_imports: Names<ServiceImport>,
    multicluster_slices: Names<MultiClusterEndpoints>,
    multicluster_endpoints: Grouped<MultiClusterEndpoints>,
    service_ips: Reverse<Service>,
    service_external_ips: Reverse<Service>,
    slices: Names<Endpoints>,
    endpoints: Grouped<Endpoints>,
    endpoint_ips: Reverse<Endpoints>,
    pods: Names<Pod>,
    pod_ips: Reverse<Pod>,
    namespaces: HashMap<Arc<str>, Namespace>,
}

fn by_name<'a, T>(map: &'a Names<T>, namespace: &str, name: &str) -> Option<&'a Arc<T>> {
    map.get(namespace)?.get(name)
}

fn put<T>(map: &mut Names<T>, namespace: Arc<str>, name: Arc<str>, object: Arc<T>) {
    map.entry(namespace).or_default().insert(name, object);
}

fn remove<T>(map: &mut Names<T>, namespace: &str, name: &str) -> Option<Arc<T>> {
    let objects = map.get_mut(namespace)?;
    let object = objects.remove(name);
    if objects.is_empty() {
        map.remove(namespace);
    }
    object
}

fn insert_reverse<T>(map: &mut Reverse<T>, key: &str, object: &Arc<T>) {
    let objects = map.entry(Arc::from(key)).or_default();
    if !objects.iter().any(|item| Arc::ptr_eq(item, object)) {
        objects.push(Arc::clone(object));
    }
}

fn remove_reverse<T>(map: &mut Reverse<T>, key: &str, object: &Arc<T>) {
    if let Some(objects) = map.get_mut(key) {
        objects.retain(|item| !Arc::ptr_eq(item, object));
        if objects.is_empty() {
            map.remove(key);
        }
    }
}

fn lookup_reverse<'a, T>(map: &'a Reverse<T>, key: &str) -> impl Iterator<Item = &'a T> {
    map.get(key).into_iter().flatten().map(Arc::as_ref)
}

impl Index {
    /// Unix timestamp of the latest change visible to Kubernetes DNS.
    pub fn serial(&self) -> u32 {
        self.serial
    }

    pub fn multicluster_serial(&self) -> u32 {
        self.multicluster_serial
    }

    fn mark_multicluster_modified(&mut self) {
        self.multicluster_serial = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
    }

    fn mark_modified(&mut self) {
        self.serial = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
    }

    fn namespace_allowed(&self, name: &str) -> bool {
        (self.allowed_namespaces.is_empty() || self.allowed_namespaces.contains(name))
            && (!self.require_namespace || self.namespaces.contains_key(name))
    }
    /// Service, EndpointSlice, endpoint-address, Pod and Namespace counts.
    pub fn counts(&self) -> (usize, usize, usize, usize, usize) {
        let services = self.services.values().map(HashMap::len).sum();
        let slices = self.slices.values().map(HashMap::len).sum();
        let addresses = self
            .slices
            .values()
            .flat_map(HashMap::values)
            .map(|slice| slice.addresses.len())
            .sum();
        let pods = self.pods.values().map(HashMap::len).sum();
        (services, slices, addresses, pods, self.namespaces.len())
    }
    pub fn service(&self, namespace: &str, name: &str) -> Option<&Service> {
        if self.namespace_allowed(namespace) {
            self.service_unfiltered(namespace, name)
        } else {
            None
        }
    }
    pub fn service_import(&self, namespace: &str, name: &str) -> Option<&ServiceImport> {
        self.namespace_allowed(namespace)
            .then(|| by_name(&self.service_imports, namespace, name))
            .flatten()
            .map(Arc::as_ref)
    }
    pub fn multicluster_endpoints(
        &self,
        namespace: &str,
        service: &str,
    ) -> impl Iterator<Item = &MultiClusterEndpoints> {
        self.multicluster_endpoints
            .get(namespace)
            .and_then(|services| services.get(service))
            .into_iter()
            .flatten()
            .map(Arc::as_ref)
            .filter(|_| self.namespace_allowed(namespace))
    }
    /// Look up a Service without applying namespace visibility restrictions.
    pub fn service_unfiltered(&self, namespace: &str, name: &str) -> Option<&Service> {
        by_name(&self.services, namespace, name).map(Arc::as_ref)
    }
    pub fn services_by_ip(&self, ip: &str) -> impl Iterator<Item = &Service> {
        self.services_by_ip_unfiltered(ip)
            .filter(|service| self.namespace_allowed(&service.namespace))
    }
    /// Look up Services by cluster IP without namespace visibility restrictions.
    pub fn services_by_ip_unfiltered(&self, ip: &str) -> impl Iterator<Item = &Service> {
        lookup_reverse(&self.service_ips, ip)
    }
    pub fn services_by_external_ip(&self, ip: &str) -> impl Iterator<Item = &Service> {
        lookup_reverse(&self.service_external_ips, ip)
            .filter(|service| self.namespace_allowed(&service.namespace))
    }
    pub fn endpoints(&self, namespace: &str, service: &str) -> impl Iterator<Item = &Endpoints> {
        self.endpoints
            .get(namespace)
            .and_then(|services| services.get(service))
            .into_iter()
            .flatten()
            .map(Arc::as_ref)
            .filter(|slice| self.namespace_allowed(&slice.namespace))
    }
    pub fn endpoints_by_ip(&self, ip: &str) -> impl Iterator<Item = &Endpoints> {
        self.endpoints_by_ip_unfiltered(ip)
            .filter(|slice| self.namespace_allowed(&slice.namespace))
    }
    /// Look up EndpointSlices by address without namespace visibility restrictions.
    pub fn endpoints_by_ip_unfiltered(&self, ip: &str) -> impl Iterator<Item = &Endpoints> {
        lookup_reverse(&self.endpoint_ips, ip)
    }
    pub fn pods_by_ip(&self, ip: &str) -> impl Iterator<Item = &Pod> {
        lookup_reverse(&self.pod_ips, ip).filter(|pod| self.namespace_allowed(&pod.namespace))
    }
    pub fn namespace(&self, name: &str) -> Option<&Namespace> {
        if self.namespace_allowed(name) {
            self.namespaces.get(name)
        } else {
            None
        }
    }

    fn delete_service(&mut self, namespace: &str, name: &str) {
        if let Some(service) = remove(&mut self.services, namespace, name) {
            for ip in &service.cluster_ips {
                remove_reverse(&mut self.service_ips, ip, &service);
            }
            for ip in &service.external_ips {
                remove_reverse(&mut self.service_external_ips, ip, &service);
            }
        }
    }
    fn delete_multicluster_endpoints(&mut self, namespace: &str, name: &str) {
        if let Some(slice) = remove(&mut self.multicluster_slices, namespace, name)
            && let Some(imports) = self.multicluster_endpoints.get_mut(namespace)
        {
            if let Some(slices) = imports.get_mut(slice.import_name.as_ref()) {
                slices.retain(|item| !Arc::ptr_eq(item, &slice));
                if slices.is_empty() {
                    imports.remove(slice.import_name.as_ref());
                }
            }
            if imports.is_empty() {
                self.multicluster_endpoints.remove(namespace);
            }
        }
    }
    fn apply_multicluster_endpoints(&mut self, slice: MultiClusterEndpoints) {
        self.delete_multicluster_endpoints(&slice.endpoints.namespace, &slice.endpoints.name);
        let slice = Arc::new(slice);
        self.multicluster_endpoints
            .entry(slice.endpoints.namespace.clone())
            .or_default()
            .entry(slice.import_name.clone())
            .or_default()
            .push(slice.clone());
        put(
            &mut self.multicluster_slices,
            slice.endpoints.namespace.clone(),
            slice.endpoints.name.clone(),
            slice,
        );
    }
    fn apply_service(&mut self, service: Service) {
        self.delete_service(&service.namespace, &service.name);
        let service = Arc::new(service);
        for ip in &service.cluster_ips {
            insert_reverse(&mut self.service_ips, ip, &service);
        }
        for ip in &service.external_ips {
            insert_reverse(&mut self.service_external_ips, ip, &service);
        }
        put(
            &mut self.services,
            service.namespace.clone(),
            service.name.clone(),
            service,
        );
    }
    fn delete_endpoints(&mut self, namespace: &str, name: &str) {
        if let Some(slice) = remove(&mut self.slices, namespace, name) {
            for address in &slice.addresses {
                remove_reverse(&mut self.endpoint_ips, &address.ip, &slice);
            }
            if let Some(services) = self.endpoints.get_mut(namespace) {
                if let Some(slices) = services.get_mut(slice.service_name.as_ref()) {
                    slices.retain(|item| !Arc::ptr_eq(item, &slice));
                    if slices.is_empty() {
                        services.remove(slice.service_name.as_ref());
                    }
                }
                if services.is_empty() {
                    self.endpoints.remove(namespace);
                }
            }
        }
    }
    fn apply_endpoints(&mut self, slice: Endpoints) {
        self.delete_endpoints(&slice.namespace, &slice.name);
        let slice = Arc::new(slice);
        for address in &slice.addresses {
            insert_reverse(&mut self.endpoint_ips, &address.ip, &slice);
        }
        self.endpoints
            .entry(slice.namespace.clone())
            .or_default()
            .entry(slice.service_name.clone())
            .or_default()
            .push(slice.clone());
        put(
            &mut self.slices,
            slice.namespace.clone(),
            slice.name.clone(),
            slice,
        );
    }
    fn delete_pod(&mut self, namespace: &str, name: &str) {
        if let Some(pod) = remove(&mut self.pods, namespace, name) {
            for ip in &pod.ips {
                remove_reverse(&mut self.pod_ips, ip, &pod);
            }
        }
    }
    fn apply_pod(&mut self, pod: Pod) {
        // CoreDNS keeps the previous Pod until its Delete event arrives.
        if pod.deleting {
            return;
        }
        self.delete_pod(&pod.namespace, &pod.name);
        let pod = Arc::new(pod);
        for ip in &pod.ips {
            insert_reverse(&mut self.pod_ips, ip, &pod);
        }
        put(&mut self.pods, pod.namespace.clone(), pod.name.clone(), pod);
    }
}

/// A read-only shared view. The closure keeps references inside the read lock.
#[derive(Clone, Default)]
pub struct Store(Arc<RwLock<Index>>);

impl Store {
    pub(crate) fn new(namespaces: &[String], require_namespace: bool) -> Self {
        let index = Index {
            allowed_namespaces: namespaces
                .iter()
                .map(|name| Arc::from(name.as_str()))
                .collect(),
            require_namespace,
            ..Default::default()
        };
        Self(Arc::new(RwLock::new(index)))
    }
    pub fn with_read<R>(&self, read: impl FnOnce(&Index) -> R) -> R {
        read(&self.0.read().unwrap())
    }
    pub(crate) fn apply_service_import(&self, object: ServiceImport) {
        let mut index = self.0.write().unwrap();
        match by_name(&index.service_imports, &object.namespace, &object.name) {
            None => index.mark_modified(),
            Some(old) if service_import_changed(old, &object) => index.mark_multicluster_modified(),
            _ => {}
        }
        put(
            &mut index.service_imports,
            object.namespace.clone(),
            object.name.clone(),
            Arc::new(object),
        );
    }
    pub(crate) fn delete_service_import(&self, namespace: &str, name: &str) {
        let mut index = self.0.write().unwrap();
        remove(&mut index.service_imports, namespace, name);
        index.mark_modified();
    }
    pub(crate) fn replace_service_imports(&self, objects: Vec<ServiceImport>) {
        let mut index = self.0.write().unwrap();
        if index
            .service_imports
            .values()
            .map(HashMap::len)
            .sum::<usize>()
            != objects.len()
            || objects
                .iter()
                .any(|o| by_name(&index.service_imports, &o.namespace, &o.name).is_none())
        {
            index.mark_modified();
        }
        if objects.iter().any(|o| {
            by_name(&index.service_imports, &o.namespace, &o.name)
                .is_some_and(|old| service_import_changed(old, o))
        }) {
            index.mark_multicluster_modified();
        }
        index.service_imports.clear();
        for object in objects {
            put(
                &mut index.service_imports,
                object.namespace.clone(),
                object.name.clone(),
                Arc::new(object),
            );
        }
    }
    pub(crate) fn apply_multicluster_endpoints(&self, object: MultiClusterEndpoints) {
        let mut index = self.0.write().unwrap();
        match by_name(
            &index.multicluster_slices,
            &object.endpoints.namespace,
            &object.endpoints.name,
        ) {
            None => index.mark_modified(),
            Some(old) if multicluster_endpoints_changed(old, &object) => {
                index.mark_multicluster_modified()
            }
            _ => {}
        }
        index.apply_multicluster_endpoints(object);
    }
    pub(crate) fn delete_multicluster_endpoints(&self, namespace: &str, name: &str) {
        let mut index = self.0.write().unwrap();
        index.delete_multicluster_endpoints(namespace, name);
        index.mark_modified();
    }
    pub(crate) fn replace_multicluster_endpoints(&self, objects: Vec<MultiClusterEndpoints>) {
        let mut index = self.0.write().unwrap();
        if index
            .multicluster_slices
            .values()
            .map(HashMap::len)
            .sum::<usize>()
            != objects.len()
            || objects.iter().any(|o| {
                by_name(
                    &index.multicluster_slices,
                    &o.endpoints.namespace,
                    &o.endpoints.name,
                )
                .is_none()
            })
        {
            index.mark_modified();
        }
        if objects.iter().any(|o| {
            by_name(
                &index.multicluster_slices,
                &o.endpoints.namespace,
                &o.endpoints.name,
            )
            .is_some_and(|old| multicluster_endpoints_changed(old, o))
        }) {
            index.mark_multicluster_modified();
        }
        index.multicluster_slices.clear();
        index.multicluster_endpoints.clear();
        for object in objects {
            index.apply_multicluster_endpoints(object);
        }
    }
    pub(crate) fn apply_service(&self, object: Service) {
        let mut index = self.0.write().unwrap();
        if service_changed(
            index.service_unfiltered(&object.namespace, &object.name),
            &object,
        ) {
            index.mark_modified();
        }
        index.apply_service(object);
    }
    pub(crate) fn delete_service(&self, namespace: &str, name: &str) {
        let mut index = self.0.write().unwrap();
        index.mark_modified();
        index.delete_service(namespace, name);
    }
    pub(crate) fn replace_services(&self, objects: Vec<Service>) {
        let mut index = self.0.write().unwrap();
        if index.services.values().map(HashMap::len).sum::<usize>() != objects.len()
            || objects.iter().any(|object| {
                service_changed(
                    index.service_unfiltered(&object.namespace, &object.name),
                    object,
                )
            })
        {
            index.mark_modified();
        }
        index.services.clear();
        index.service_ips.clear();
        index.service_external_ips.clear();
        for object in objects {
            index.apply_service(object);
        }
    }
    pub(crate) fn apply_endpoints(&self, object: Endpoints) {
        let mut index = self.0.write().unwrap();
        if endpoints_changed(
            by_name(&index.slices, &object.namespace, &object.name).map(Arc::as_ref),
            &object,
        ) {
            index.mark_modified();
        }
        index.apply_endpoints(object);
    }
    pub(crate) fn delete_endpoints(&self, namespace: &str, name: &str) {
        let mut index = self.0.write().unwrap();
        index.mark_modified();
        index.delete_endpoints(namespace, name);
    }
    pub(crate) fn replace_endpoints<R>(
        &self,
        objects: Vec<Endpoints>,
        read: impl FnOnce(&Index) -> R,
    ) -> R {
        let mut index = self.0.write().unwrap();
        if index.slices.values().map(HashMap::len).sum::<usize>() != objects.len()
            || objects.iter().any(|object| {
                endpoints_changed(
                    by_name(&index.slices, &object.namespace, &object.name).map(Arc::as_ref),
                    object,
                )
            })
        {
            index.mark_modified();
        }
        index.slices.clear();
        index.endpoints.clear();
        index.endpoint_ips.clear();
        for object in objects {
            index.apply_endpoints(object);
        }
        read(&index)
    }
    pub(crate) fn apply_pod(&self, object: Pod) {
        let mut index = self.0.write().unwrap();
        if !object.deleting
            && pod_changed(
                by_name(&index.pods, &object.namespace, &object.name).map(Arc::as_ref),
                &object,
            )
        {
            index.mark_modified();
        }
        index.apply_pod(object);
    }
    pub(crate) fn delete_pod(&self, namespace: &str, name: &str) {
        let mut index = self.0.write().unwrap();
        index.mark_modified();
        index.delete_pod(namespace, name);
    }
    pub(crate) fn replace_pods(&self, objects: Vec<Pod>) {
        let mut index = self.0.write().unwrap();
        let objects: Vec<_> = objects
            .into_iter()
            .filter_map(|object| {
                if object.deleting {
                    by_name(&index.pods, &object.namespace, &object.name)
                        .map(|previous| previous.as_ref().clone())
                } else {
                    Some(object)
                }
            })
            .collect();
        if index.pods.values().map(HashMap::len).sum::<usize>() != objects.len()
            || objects.iter().any(|object| {
                pod_changed(
                    by_name(&index.pods, &object.namespace, &object.name).map(Arc::as_ref),
                    object,
                )
            })
        {
            index.mark_modified();
        }
        index.pods.clear();
        index.pod_ips.clear();
        for object in objects {
            index.apply_pod(object);
        }
    }
    pub(crate) fn apply_namespace(&self, object: Namespace) {
        self.0
            .write()
            .unwrap()
            .namespaces
            .insert(object.name.clone(), object);
    }
    pub(crate) fn delete_namespace(&self, name: &str) {
        self.0.write().unwrap().namespaces.remove(name);
    }
    pub(crate) fn replace_namespaces(&self, objects: Vec<Namespace>) {
        self.0.write().unwrap().namespaces = objects
            .into_iter()
            .map(|object| (object.name.clone(), object))
            .collect();
    }
}

fn service_changed(old: Option<&Service>, new: &Service) -> bool {
    old.is_none_or(|old| {
        old.version != new.version
            && (old.external_name != new.external_name || old.ports != new.ports)
    })
}

fn service_import_changed(old: &ServiceImport, new: &ServiceImport) -> bool {
    old.version != new.version && (old.service_type != new.service_type || old.ports != new.ports)
}

fn multicluster_endpoints_changed(
    old: &MultiClusterEndpoints,
    new: &MultiClusterEndpoints,
) -> bool {
    old.endpoints.version != new.endpoints.version
        && (old.cluster_id != new.cluster_id
            || endpoints_changed(Some(&old.endpoints), &new.endpoints))
}

fn endpoints_changed(old: Option<&Endpoints>, new: &Endpoints) -> bool {
    old.is_none_or(|old| {
        old.version != new.version
            && (old.ports != new.ports
                || old.zones != new.zones
                || old.addresses.len() != new.addresses.len()
                || old
                    .addresses
                    .iter()
                    .zip(&new.addresses)
                    .any(|(a, b)| a.ip != b.ip || a.hostname != b.hostname))
    })
}

fn pod_changed(old: Option<&Pod>, new: &Pod) -> bool {
    old.is_none_or(|old| old.version != new.version && old.ips != new.ips)
}
