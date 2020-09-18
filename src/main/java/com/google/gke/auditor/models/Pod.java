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

import com.google.gke.auditor.system.Logger;
import com.google.gke.auditor.system.ResourceType;
import io.kubernetes.client.openapi.models.V1Affinity;
import io.kubernetes.client.openapi.models.V1Container;
import io.kubernetes.client.openapi.models.V1NodeAffinity;
import io.kubernetes.client.openapi.models.V1NodeSelector;
import io.kubernetes.client.openapi.models.V1NodeSelectorTerm;
import io.kubernetes.client.openapi.models.V1Pod;
import io.kubernetes.client.openapi.models.V1PodSpec;
import io.kubernetes.client.openapi.models.V1PodStatus;
import io.kubernetes.client.openapi.models.V1Toleration;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * A wrapper class around {@link V1Pod}.
 */
public class Pod extends Asset {

  /**
   * API Pod reference.
   */
  private final V1Pod pod;

  /**
   * Initialize the Pod.
   * @param pod api pod reference
   */
  public Pod(V1Pod pod) {
    this.pod = pod;
  }

  @Override
  public Logger.Builder getReport() {
    return Logger.builder()
        .addMessage("Pod", getAssetName(), Logger.Color.RED);
  }

  @Override
  public String getAssetName() {
    if (pod.getMetadata() != null) {
      return pod.getMetadata().getName();
    }
    return null;
  }

  @Override
  public String toString() {
    return String.format("Pod: %s", getAssetName());
  }

  @Override
  public ResourceType getResourceType() {
    return ResourceType.POD;
  }

  /**
   * Returns a map of node selectors (key-value pairs), or an empty map if there is none.
   * @return a map of node selectors
   */
  public Map<String, String> getNodeSelectors() {
    return Optional.ofNullable(pod.getSpec())
        .map(V1PodSpec::getNodeSelector)
        .orElse(Collections.emptyMap());
  }

  /**
   * Returns a list of node affinity selector terms, or an empty list if there is none.
   * @return a list of node affinity selector terms
   */
  public List<V1NodeSelectorTerm> getNodeAffinitySelectorTerms() {
    return Optional.ofNullable(pod.getSpec())
        .map(V1PodSpec::getAffinity)
        .map(V1Affinity::getNodeAffinity)
        .map(V1NodeAffinity::getRequiredDuringSchedulingIgnoredDuringExecution)
        .map(V1NodeSelector::getNodeSelectorTerms)
        .orElse(Collections.emptyList());
  }

  /**
   * Returns a list of pod {@link V1Toleration}s, or an empty list if there is none.
   * @return a list of tolerations
   */
  public List<V1Toleration> getTolerations() {
    return Optional.ofNullable(pod.getSpec())
        .map(V1PodSpec::getTolerations)
        .orElse(Collections.emptyList());
  }

  /**
   * Returns the namespaced service account name associated with this pod.
   * @return service account name
   */
  public String getServiceAccount() {
    if (pod.getSpec() != null && pod.getMetadata() != null) {
      return String
          .format("%s/%s", pod.getMetadata().getNamespace(), pod.getSpec().getServiceAccountName());
    }
    return null;
  }

  /**
   * Returns the name of the node on which the pod is scheduled.
   * @return node name
   */
  public String getNodeName() {
    if (pod.getSpec() != null) {
      return pod.getSpec().getNodeName();
    }
    return null;
  }

  /**
   * Returns namespaced pod name in the format pod_namespace/pod_name.
   * @return namespaced pod name
   */
  public String getNamespacedPod() {
    if (pod.getMetadata() != null) {
      return String.format("%s/%s", pod.getMetadata().getNamespace(), pod.getMetadata().getName());
    }
    return null;
  }

  /**
   * Returns the pod IP.
   * @return pod IP
   */
  public String getPodIP() {
    return Optional.ofNullable(pod.getStatus())
        .map(V1PodStatus::getPodIP)
        .orElse("None");
  }

  /**
   * Returns a list of pod {@link V1Container}s, or an empty list if there is none.
   * @return a list of containers
   */
  public List<V1Container> getContainers() {
    return Optional.ofNullable(pod.getSpec())
        .map(V1PodSpec::getContainers)
        .orElse(Collections.emptyList());
  }

}
