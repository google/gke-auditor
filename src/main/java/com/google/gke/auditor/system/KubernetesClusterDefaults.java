// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.gke.auditor.system;

import java.util.Arrays;
import java.util.HashSet;

/**
 * Utility class for storing Kubernetes defaults.
 * <p>
 * K8s defaults in the scope of this tool are system settings configured when a default cluster is
 * created. Some of these settings can be considered as vulnerabilities by the tool, so there exists
 * a possibility of excluding them in the audit.
 */
public class KubernetesClusterDefaults {

  /**
   * ClusterRoleBindings present in a default cluster.
   */
  private static final HashSet<String> defaultClusterRoleBindings = new HashSet<>(
      Arrays.asList("cluster-admin",
          "cluster-autoscaler-updateinfo",
          "default:kmsplugin",
          "event-exporter-rb",
          "gce:beta:kubelet-certificate-bootstrap",
          "gce:beta:kubelet-certificate-rotation",
          "gce:cloud-provider",
          "heapster-binding",
          "kube-apiserver-kubelet-api-admin",
          "kubelet-bootstrap",
          "kubelet-bootstrap-certificate-bootstrap",
          "kubelet-bootstrap-node-bootstrapper",
          "kubelet-cluster-admin",
          "master-monitoring-role-binding",
          "metrics-server:system:auth-delegator",
          "npd-binding",
          "stackdriver:fluentd-gcp",
          "stackdriver:metadata-agent",
          "storage-version-migration-crd-creator",
          "storage-version-migration-initializer",
          "storage-version-migration-migrator",
          "storage-version-migration-trigger",
          "system:basic-user",
          "system:clustermetrics",
          "system:controller:attachdetach-controller",
          "system:controller:certificate-controller",
          "system:controller:clusterrole-aggregation-controller",
          "system:controller:cronjob-controller",
          "system:controller:daemon-set-controller",
          "system:controller:deployment-controller",
          "system:controller:disruption-controller",
          "system:controller:endpoint-controller",
          "system:controller:expand-controller",
          "system:controller:generic-garbage-collector",
          "system:controller:glbc",
          "system:controller:horizontal-pod-autoscaler",
          "system:controller:job-controller",
          "system:controller:namespace-controller",
          "system:controller:node-controller",
          "system:controller:persistent-volume-binder",
          "system:controller:pod-garbage-collector",
          "system:controller:pv-protection-controller",
          "system:controller:pvc-protection-controller",
          "system:controller:replicaset-controller",
          "system:controller:replication-controller",
          "system:controller:resourcequota-controller",
          "system:controller:route-controller",
          "system:controller:service-account-controller",
          "system:controller:service-controller",
          "system:controller:statefulset-controller",
          "system:controller:ttl-controller",
          "system:discovery",
          "system:gcp-controller-manager",
          "system:gke-common-webhooks",
          "system:gke-master-resourcequota",
          "system:gke-uas-adapter",
          "system:gke-uas-collection-reader",
          "system:gke-uas-hpa-controller",
          "system:gke-uas-metrics-reader",
          "system:glbc-status",
          "system:kube-controller-manager",
          "system:kube-dns",
          "system:kube-dns-autoscaler",
          "system:kube-scheduler",
          "system:kubestore-collector",
          "system:managed-certificate-controller",
          "system:metrics-server",
          "system:node",
          "system:node-proxier",
          "system:public-info-viewer",
          "system:resource-tracker",
          "system:slo-monitor",
          "system:volume-scheduler",
          "uas-hpa-external-metrics-reader"));

  /**
   * RoleBindings present in a default cluster.
   */
  private static final HashSet<String> defaultRoleBindings = new HashSet<>(
      Arrays.asList("kube-public/system:controller:bootstrap-signer",
          "kube-system/fluentd-gcp-scaler-binding",
          "kube-system/gce:cloud-provider",
          "kube-system/heapster-binding",
          "kube-system/metrics-server-auth-reader",
          "kube-system/system::extension-apiserver-authentication-reader",
          "kube-system/system::leader-locking-kube-controller-manager",
          "kube-system/system::leader-locking-kube-scheduler",
          "kube-system/system:controller:bootstrap-signer",
          "kube-system/system:controller:cloud-provider",
          "kube-system/system:controller:glbc",
          "kube-system/system:controller:token-cleaner"));

  /**
   * ClusterRoles present in a default cluster.
   */
  private static final HashSet<String> defaultClusterRoles = new HashSet<>(
      Arrays.asList("admin",
          "cloud-provider",
          "cluster-admin",
          "edit",
          "gce:beta:kubelet-certificate-bootstrap",
          "gce:beta:kubelet-certificate-rotation",
          "gce:cloud-provider",
          "kubelet-api-admin",
          "read-updateinfo",
          "stackdriver:fluentd-gcp",
          "stackdriver:metadata-agent",
          "storage-version-migration-crd-creator",
          "storage-version-migration-initializer",
          "storage-version-migration-migrator",
          "storage-version-migration-trigger",
          "system:aggregate-to-admin",
          "system:aggregate-to-edit",
          "system:aggregate-to-view",
          "system:auth-delegator",
          "system:basic-user",
          "system:certificates.k8s.io:certificatesigningrequests:nodeclient",
          "system:certificates.k8s.io:certificatesigningrequests:selfnodeclient",
          "system:clustermetrics",
          "system:controller:attachdetach-controller",
          "system:controller:certificate-controller",
          "system:controller:clusterrole-aggregation-controller",
          "system:controller:cronjob-controller",
          "system:controller:daemon-set-controller",
          "system:controller:deployment-controller",
          "system:controller:disruption-controller",
          "system:controller:endpoint-controller",
          "system:controller:expand-controller",
          "system:controller:generic-garbage-collector",
          "system:controller:glbc",
          "system:controller:horizontal-pod-autoscaler",
          "system:controller:job-controller",
          "system:controller:namespace-controller",
          "system:controller:node-controller",
          "system:controller:persistent-volume-binder",
          "system:controller:pod-garbage-collector",
          "system:controller:pv-protection-controller",
          "system:controller:pvc-protection-controller",
          "system:controller:replicaset-controller",
          "system:controller:replication-controller",
          "system:controller:resourcequota-controller",
          "system:controller:route-controller",
          "system:controller:service-account-controller",
          "system:controller:service-controller",
          "system:controller:statefulset-controller",
          "system:controller:ttl-controller",
          "system:csi-external-attacher",
          "system:csi-external-provisioner",
          "system:discovery",
          "system:gcp-controller-manager",
          "system:gke-common-webhooks",
          "system:gke-master-resourcequota",
          "system:gke-uas-adapter",
          "system:gke-uas-collection-reader",
          "system:gke-uas-metrics-reader",
          "system:glbc-status",
          "system:heapster",
          "system:kmsplugin",
          "system:kube-aggregator",
          "system:kube-controller-manager",
          "system:kube-dns",
          "system:kube-dns-autoscaler",
          "system:kube-scheduler",
          "system:kubelet-api-admin",
          "system:kubestore-collector",
          "system:managed-certificate-controller",
          "system:master-monitoring-role",
          "system:metrics-server",
          "system:node",
          "system:node-bootstrapper",
          "system:node-problem-detector",
          "system:node-proxier",
          "system:persistent-volume-provisioner",
          "system:public-info-viewer",
          "system:resource-tracker",
          "system:slo-monitor",
          "system:volume-scheduler",
          "view"));
  /**
   * Roles present in a default cluster.
   */
  private static final HashSet<String> defaultRoles = new HashSet<>(Arrays
      .asList("kube-public/system:controller:bootstrap-signer",
          "kube-system/cloud-provider",
          "kube-system/extension-apiserver-authentication-reader",
          "kube-system/gce:cloud-provider",
          "kube-system/system::leader-locking-kube-controller-manager",
          "kube-system/system::leader-locking-kube-scheduler",
          "kube-system/system:controller:bootstrap-signer",
          "kube-system/system:controller:cloud-provider",
          "kube-system/system:controller:glbc",
          "kube-system/system:controller:token-cleaner",
          "kube-system/system:fluentd-gcp-scaler",
          "kube-system/system:pod-nanny"));
  /**
   * ServiceAccounts present in a default cluster.
   */
  private static final HashSet<String> defaultServiceAccounts = new HashSet<>(
      Arrays.asList("attachdetach-controller",
          "certificate-controller",
          "cloud-provider",
          "clusterrole-aggregation-controller",
          "cronjob-controller",
          "daemon-set-controller",
          "default",
          "default",
          "default",
          "default",
          "deployment-controller",
          "disruption-controller",
          "endpoint-controller",
          "event-exporter-sa",
          "expand-controller",
          "fluentd-gcp",
          "fluentd-gcp-scaler",
          "generic-garbage-collector",
          "heapster",
          "horizontal-pod-autoscaler",
          "job-controller",
          "kube-dns",
          "kube-dns-autoscaler",
          "metadata-agent",
          "metadata-proxy",
          "metrics-server",
          "namespace-controller",
          "node-controller",
          "persistent-volume-binder",
          "pod-garbage-collector",
          "prometheus-to-sd",
          "pv-protection-controller",
          "pvc-protection-controller",
          "replicaset-controller",
          "replication-controller",
          "resourcequota-controller",
          "service-account-controller",
          "service-controller",
          "statefulset-controller",
          "ttl-controller"));

  /**
   * Gets the default resources of the given asset type.
   * @param assetType type of the resource to return defaults of
   * @return set of default resources of the given type
   */
  public static HashSet<String> getKubernetesDefaults(ResourceType assetType) {
    if (assetType == null) {
      return new HashSet<>();
    }

    switch (assetType) {
      case CLUSTER_ROLE_BINDING:
        return defaultClusterRoleBindings;
      case CLUSTER_ROLE:
        return defaultClusterRoles;
      case SERVICE_ACCOUNT:
        return defaultServiceAccounts;
      case ROLE:
        return defaultRoles;
      case ROLE_BINDING:
        return defaultRoleBindings;
      default:
        return new HashSet<>();
    }
  }

}
