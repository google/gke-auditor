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
import io.kubernetes.client.openapi.models.V1beta1PolicyRule;
import io.kubernetes.client.openapi.models.V1beta1Role;
import java.util.Collections;
import java.util.List;

/**
 * A wrapper class around {@link V1beta1Role}.
 */
public class Role extends KubernetesRole {

  /**
   * API Role reference.
   */
  private final V1beta1Role role;

  /**
   * Initialize the Role.
   * @param role api role reference
   */
  public Role(V1beta1Role role) {
    this.role = role;
  }

  @Override
  public Logger.Builder getReport() {
    return Logger.builder().addMessage("Role", getAssetName(), Logger.Color.RED)
        .addSubMessages(super.getReport());
  }

  @Override
  public String getAssetName() {
    if (role.getMetadata() != null) {
      return String
          .format("%s/%s", role.getMetadata().getNamespace(), role.getMetadata().getName());
    }
    return null;
  }

  @Override
  public String toString() {
    return String.format("Role: %s", getAssetName());
  }

  @Override
  public ResourceType getResourceType() {
    return ResourceType.ROLE;
  }

  @Override
  public List<V1beta1PolicyRule> getRules() {
    if (role.getRules() == null) {
      return Collections.emptyList();
    }

    return role.getRules();
  }

}
