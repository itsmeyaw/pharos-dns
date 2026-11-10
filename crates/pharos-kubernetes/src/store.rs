#[cfg(test)]
mod tests {
    use super::Store;
    use crate::object::{Endpoints, Namespace, Pod, Service};
    use k8s_openapi::api::{core::v1, discovery::v1::EndpointSlice};
    use serde_json::json;

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
}
// Incremental indices shared by watchers and DNS readers.

use crate::object::{Endpoints, Namespace, Pod, Service};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

type Names<T> = HashMap<Arc<str>, HashMap<Arc<str>, Arc<T>>>;
type Reverse<T> = HashMap<Arc<str>, Vec<Arc<T>>>;
type Grouped<T> = HashMap<Arc<str>, Reverse<T>>;

#[derive(Default)]
pub struct Index {
    services: Names<Service>,
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
        by_name(&self.services, namespace, name).map(Arc::as_ref)
    }
    pub fn services_by_ip(&self, ip: &str) -> impl Iterator<Item = &Service> {
        lookup_reverse(&self.service_ips, ip)
    }
    pub fn services_by_external_ip(&self, ip: &str) -> impl Iterator<Item = &Service> {
        lookup_reverse(&self.service_external_ips, ip)
    }
    pub fn endpoints(&self, namespace: &str, service: &str) -> impl Iterator<Item = &Endpoints> {
        self.endpoints
            .get(namespace)
            .and_then(|services| services.get(service))
            .into_iter()
            .flatten()
            .map(Arc::as_ref)
    }
    pub fn endpoints_by_ip(&self, ip: &str) -> impl Iterator<Item = &Endpoints> {
        lookup_reverse(&self.endpoint_ips, ip)
    }
    pub fn pods_by_ip(&self, ip: &str) -> impl Iterator<Item = &Pod> {
        lookup_reverse(&self.pod_ips, ip)
    }
    pub fn namespace(&self, name: &str) -> Option<&Namespace> {
        self.namespaces.get(name)
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
    pub fn with_read<R>(&self, read: impl FnOnce(&Index) -> R) -> R {
        read(&self.0.read().unwrap())
    }
    pub(crate) fn apply_service(&self, object: Service) {
        self.0.write().unwrap().apply_service(object);
    }
    pub(crate) fn delete_service(&self, namespace: &str, name: &str) {
        self.0.write().unwrap().delete_service(namespace, name);
    }
    pub(crate) fn replace_services(&self, objects: Vec<Service>) {
        let mut index = self.0.write().unwrap();
        index.services.clear();
        index.service_ips.clear();
        index.service_external_ips.clear();
        for object in objects {
            index.apply_service(object);
        }
    }
    pub(crate) fn apply_endpoints(&self, object: Endpoints) {
        self.0.write().unwrap().apply_endpoints(object);
    }
    pub(crate) fn delete_endpoints(&self, namespace: &str, name: &str) {
        self.0.write().unwrap().delete_endpoints(namespace, name);
    }
    pub(crate) fn replace_endpoints(&self, objects: Vec<Endpoints>) {
        let mut index = self.0.write().unwrap();
        index.slices.clear();
        index.endpoints.clear();
        index.endpoint_ips.clear();
        for object in objects {
            index.apply_endpoints(object);
        }
    }
    pub(crate) fn apply_pod(&self, object: Pod) {
        self.0.write().unwrap().apply_pod(object);
    }
    pub(crate) fn delete_pod(&self, namespace: &str, name: &str) {
        self.0.write().unwrap().delete_pod(namespace, name);
    }
    pub(crate) fn replace_pods(&self, objects: Vec<Pod>) {
        let mut index = self.0.write().unwrap();
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
