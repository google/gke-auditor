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
import io.kubernetes.client.openapi.models.V1beta1ClusterRole;
import io.kubernetes.client.openapi.models.V1beta1PolicyRule;
import java.util.Collections;
import java.util.List;

/**
 * A wrapper class around {@link V1beta1ClusterRole}.
 */
public class ClusterRole extends KubernetesRole {

  /**
   * API ClusterRole reference.
   */
  private final V1beta1ClusterRole clusterRole;

  /**
   * Initialize the ClusterRole.
   * @param clusterRole api ClusterRole reference
   */
  public ClusterRole(V1beta1ClusterRole clusterRole) {
    this.clusterRole = clusterRole;
  }

  @Override
  public Logger.Builder getReport() {
    return Logger.builder().addMessage("ClusterRole", getAssetName(), Logger.Color.RED)
        .addSubMessages(super.getReport());
  }

  @Override
  public String toString() {
    return "ClusterRole: " + getAssetName();
  }

  @Override
  public String getAssetName() {
    if (clusterRole.getMetadata() != null) {
      return clusterRole.getMetadata().getName();
    }
    return null;
  }

  @Override
  public ResourceType getResourceType() {
    return ResourceType.CLUSTER_ROLE;
  }

  @Override
  public List<V1beta1PolicyRule> getRules() {
    if (clusterRole.getRules() != null) {
      return clusterRole.getRules();
    }
    return Collections.emptyList();
  }

}
