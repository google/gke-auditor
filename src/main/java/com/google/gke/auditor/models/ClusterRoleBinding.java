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
import io.kubernetes.client.openapi.models.V1beta1ClusterRoleBinding;
import io.kubernetes.client.openapi.models.V1beta1RoleRef;
import io.kubernetes.client.openapi.models.V1beta1Subject;
import java.util.List;

/**
 * A wrapper class around {@link V1beta1ClusterRoleBinding}.
 */
public class ClusterRoleBinding extends KubernetesRoleBinding {

  /**
   * API ClusterRoleBinding reference.
   */
  private final V1beta1ClusterRoleBinding clusterRoleBinding;

  /**
   * Initialize the ClusterRoleBinding.
   * @param clusterRoleBinding api ClusterRoleBinding reference
   */
  public ClusterRoleBinding(V1beta1ClusterRoleBinding clusterRoleBinding) {
    this.clusterRoleBinding = clusterRoleBinding;
  }

  @Override
  public Logger.Builder getReport() {
    return Logger.builder().addMessage("ClusterRoleBinding", getAssetName(), Logger.Color.RED)
        .addSubMessages(super.getReport());
  }

  @Override
  public String toString() {
    return "ClusterRoleBinding: " + getAssetName();
  }

  @Override
  public String getAssetName() {
    if (clusterRoleBinding.getMetadata() != null) {
      return clusterRoleBinding.getMetadata().getName();
    }
    return null;
  }

  @Override
  public ResourceType getResourceType() {
    return ResourceType.CLUSTER_ROLE_BINDING;
  }

  @Override
  public List<V1beta1Subject> getSubjects() {
    return clusterRoleBinding.getSubjects();
  }

  @Override
  public V1beta1RoleRef getRoleRef() {
    return clusterRoleBinding.getRoleRef();
  }

  @Override
  public String getRoleRefName() {
    return clusterRoleBinding.getRoleRef().getName();
  }

}
