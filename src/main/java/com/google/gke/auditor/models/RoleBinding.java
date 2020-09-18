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
import com.google.gke.auditor.system.Logger.Color;
import com.google.gke.auditor.system.ResourceType;
import io.kubernetes.client.openapi.models.V1beta1RoleBinding;
import io.kubernetes.client.openapi.models.V1beta1RoleRef;
import io.kubernetes.client.openapi.models.V1beta1Subject;
import java.util.List;

/**
 * A wrapper class around {@link V1beta1RoleBinding}.
 */
public class RoleBinding extends KubernetesRoleBinding {

  /**
   * API RoleBinding reference.
   */
  private final V1beta1RoleBinding roleBinding;

  /**
   * Initialize the RoleBinding.
   * @param roleBinding role binding api reference
   */
  public RoleBinding(V1beta1RoleBinding roleBinding) {
    this.roleBinding = roleBinding;
  }

  @Override
  public Logger.Builder getReport() {
    return Logger.builder().addMessage("RoleBinding", getAssetName(), Color.RED)
        .addSubMessages(super.getReport());
  }

  @Override
  public String toString() {
    return String.format("RoleBinding: %s", getAssetName());
  }

  @Override
  public String getAssetName() {
    if (roleBinding.getMetadata() != null) {
      return String.format("%s/%s", roleBinding.getMetadata().getNamespace(),
          roleBinding.getMetadata().getName());
    }
    return null;
  }

  @Override
  public ResourceType getResourceType() {
    return ResourceType.ROLE_BINDING;
  }

  @Override
  public V1beta1RoleRef getRoleRef() {
    return roleBinding.getRoleRef();
  }

  @Override
  public List<V1beta1Subject> getSubjects() {
    return roleBinding.getSubjects();
  }

  @Override
  public String getRoleRefName() {
    if (roleBinding.getMetadata() != null) {
      return String.format("%s/%s", roleBinding.getMetadata().getNamespace(),
          roleBinding.getRoleRef().getName());
    }
    return null;
  }

}
