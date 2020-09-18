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

package com.google.gke.auditor.models;

import com.google.gke.auditor.configs.util.DetectorUtil;
import com.google.gke.auditor.system.Logger;
import com.google.gke.auditor.system.ResourceType;
import io.kubernetes.client.openapi.models.V1Container;
import io.kubernetes.client.openapi.models.V1VolumeMount;
import io.kubernetes.client.openapi.models.V1beta1PolicyRule;
import java.util.Collections;
import java.util.List;

/**
 * Represents a binding between a {@link Node}, a {@link Pod} scheduled on that node, service
 * account associated with that pod, and {@link KubernetesRole} and {@link KubernetesRoleBinding}
 * associated with that service account.
 */
public class Dependency extends Asset {

  /**
   * Either {@link ClusterRoleBinding} or {@link RoleBinding} between the role and the
   * serviceAccount.
   */
  private final KubernetesRoleBinding roleBinding;
  /**
   * either {@link ClusterRole} or {@link Role}.
   */
  private final KubernetesRole role;
  /**
   * Service account with permissions on resources.
   */
  private final String serviceAccount;
  /**
   * Node being audited.
   */
  private final Node node;
  /**
   * Pod scheduled on the node.
   */
  private final Pod pod;

  /**
   * A list of rules found to be escalating by the tool.
   */
  private List<V1beta1PolicyRule> escalatingRules = Collections.emptyList();

  /**
   * Initialize the Dependency.
   * @param roleBinding    roleBinding (either {@link ClusterRoleBinding} or {@link RoleBinding})
   * @param role           role (either {@link ClusterRole} or {@link Role})
   * @param serviceAccount serviceAccount
   * @param node           node
   * @param pod            pod
   */
  public Dependency(KubernetesRoleBinding roleBinding,
      KubernetesRole role,
      String serviceAccount,
      Node node,
      Pod pod) {
    this.roleBinding = roleBinding;
    this.role = role;
    this.serviceAccount = serviceAccount;
    this.node = node;
    this.pod = pod;
  }

  /**
   * Sets the list of escalating rules found by the tool.
   */
  public void setEscalatingRules(List<V1beta1PolicyRule> escalatingRules) {
    this.escalatingRules = escalatingRules;
  }

  @Override
  public Logger.Builder getReport() {
    Logger.Builder builder = Logger.builder()
        .addMessage("Node", node.getAssetName());
    Logger.Builder podBuilder = Logger.builder()
        .addMessage("Pod", pod.getNamespacedPod() + " " + pod.getPodIP());

    Logger.Builder containerBuilder = Logger.builder();
    Logger.Builder volumeMountBuilder = Logger.builder();
    Logger.Builder serviceAccountBuilder = Logger.builder();

    List<V1Container> containers = pod.getContainers();
    for (V1Container container : containers) {
      containerBuilder.addMessage("Container",
          container.getName() + ", image: " + container.getImage());

      List<V1VolumeMount> volumeMounts = container.getVolumeMounts();
      if (volumeMounts != null) {
        for (V1VolumeMount volumeMount : volumeMounts) {
          if (volumeMount == null) {
            continue;
          }

          String mount = volumeMount.getName() + ", mountPath: " + volumeMount.getMountPath();
          if (volumeMount.getReadOnly() != null) {
            mount += volumeMount.getReadOnly() ? "[ro]" : "[rw]";
          }
          volumeMountBuilder.addMessage("VolumeMount", mount);
        }
      }
    }

    serviceAccountBuilder.addMessage("Service Account", serviceAccount);

    for (V1beta1PolicyRule rule : escalatingRules) {
      serviceAccountBuilder.addSubMessage("does",
          rule.getVerbs() + " on " + DetectorUtil.getAPIGroupResources(rule), Logger.Color.RED);
    }
    serviceAccountBuilder.addSubMessageLineBreak();

    builder.addSubMessages(podBuilder);
    podBuilder.addSubMessages(containerBuilder);
    containerBuilder.addSubMessages(volumeMountBuilder);
    volumeMountBuilder.addSubMessages(serviceAccountBuilder);
    return builder;
  }

  /**
   * Retrieve the role ({@link ClusterRole} or {@link Role}) of this Dependency.
   * @return role
   */
  public KubernetesRole getRole() {
    return role;
  }

  @Override
  public String getAssetName() {
    return String
        .format("Node: %s, Pod: %s, Service Account: %s", node.getAssetName(), pod.getAssetName(),
            serviceAccount);
  }

  @Override
  public ResourceType getResourceType() {
    return ResourceType.DEPENDENCY_REPORT;
  }

}
