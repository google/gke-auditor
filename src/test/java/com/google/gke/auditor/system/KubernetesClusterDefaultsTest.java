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


import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.HashSet;
import org.junit.jupiter.api.Test;

/**
 * A test for {@link KubernetesClusterDefaults}.
 */
public class KubernetesClusterDefaultsTest {

  @Test
  public void getKubernetesClusterDefaultsNullTest() {
    assertThat(KubernetesClusterDefaults.getKubernetesDefaults(null).isEmpty());
  }

  @Test
  public void getKubernetesClusterDefaultsClusterRoleTest() {
    HashSet<String> defaultClusterRoles = new HashSet<>(
        Arrays.asList("admin",
            "edit",
            "cluster-admin",
            "kubelet-api-admin",
            "stackdriver:metadata-agent",
            "storage-version-migration-migrator",
            "system:aggregate-to-edit",
            "system:controller:expand-controller",
            "system:controller:glbc",
            "system:controller:persistent-volume-binder",
            "system:controller:clusterrole-aggregation-controller",
            "system:controller:daemon-set-controller",
            "system:controller:disruption-controller",
            "system:controller:generic-garbage-collector",
            "system:controller:horizontal-pod-autoscaler",
            "system:controller:job-controller",
            "system:controller:namespace-controller",
            "system:controller:resourcequota-controller",
            "system:controller:replicaset-controller",
            "system:controller:replication-controller",
            "system:controller:statefulset-controller",
            "system:kmsplugin",
            "system:kube-controller-manager",
            "system:kubelet-api-admin",
            "system:kubestore-collector",
            "system:gcp-controller-manager",
            "system:gke-common-webhooks",
            "system:gke-master-resourcequota",
            "system:glbc-status",
            "system:managed-certificate-controller",
            "system:node"));

    assertThat(KubernetesClusterDefaults.getKubernetesDefaults(ResourceType.CLUSTER_ROLE)
        .containsAll(defaultClusterRoles));
  }

  @Test
  public void getKubernetesClusterDefaultsNonExistingDefaultTest() {
    assertThat(
        KubernetesClusterDefaults.getKubernetesDefaults(ResourceType.DEPENDENCY_REPORT).isEmpty());
  }

}