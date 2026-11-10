# Corefile fixture sources

These are the Corefile values from the upstream ConfigMaps, with YAML indentation
removed and a final newline in each file. They represent the pinned versions,
not necessarily the latest defaults.

- `kubeadm.Corefile`: Kubernetes v1.33.0 [kubeadm ConfigMap template](https://github.com/kubernetes/kubernetes/blob/v1.33.0/cmd/kubeadm/app/phases/addons/dns/manifests.go). Rendered `.DNSDomain` as `cluster.local`, the [kubeadm default](https://github.com/kubernetes/kubernetes/blob/v1.33.0/cmd/kubeadm/app/apis/kubeadm/v1beta4/defaults.go); the nonempty-domain cache block is included.
- `kubernetes-addon.Corefile`: Kubernetes v1.33.0 [cluster/addons/dns/coredns base manifest](https://github.com/kubernetes/kubernetes/blob/v1.33.0/cluster/addons/dns/coredns/coredns.yaml.base). Replaced `__DNS__DOMAIN__` (or `$DNS_DOMAIN` in the [generated sed manifest](https://github.com/kubernetes/kubernetes/blob/v1.33.0/cluster/addons/dns/coredns/coredns.yaml.sed)) with the conventional `cluster.local` domain.
- `coredns-helm.Corefile`: CoreDNS chart 1.50.4 [default values](https://github.com/coredns/helm/blob/coredns-1.50.4/charts/coredns/values.yaml) and [ConfigMap template](https://github.com/coredns/helm/blob/coredns-1.50.4/charts/coredns/templates/configmap.yaml), rendered with unmodified values. No placeholder substitutions were needed; the chart's YAML `|-` strips the final newline, which is restored in the fixture.
- `k3s.Corefile`: k3s v1.33.0+k3s1 [packaged manifest](https://github.com/k3s-io/k3s/blob/v1.33.0%2Bk3s1/manifests/coredns.yaml). Replaced `%{CLUSTER_DOMAIN}%` with `cluster.local`, the [k3s default](https://github.com/k3s-io/k3s/blob/v1.33.0%2Bk3s1/pkg/cli/cmds/server.go). Both custom configuration imports are retained; their files are not part of this fixture.
