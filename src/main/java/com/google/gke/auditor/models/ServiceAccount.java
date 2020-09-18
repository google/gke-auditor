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
import io.kubernetes.client.openapi.models.V1ServiceAccount;
import org.apache.commons.lang.BooleanUtils;

/**
 * A wrapper class around {@link V1ServiceAccount}.
 */
public class ServiceAccount extends Asset {

  /**
   * API ServiceAccount reference.
   */
  private final V1ServiceAccount serviceAccount;

  /**
   * Initialize the ServiceAccount
   * @param serviceAccount api service account reference
   */
  public ServiceAccount(V1ServiceAccount serviceAccount) {
    this.serviceAccount = serviceAccount;
  }

  @Override
  public Logger.Builder getReport() {
    return Logger.builder().addMessage("ServiceAccount", getAssetName(), Color.RED);
  }

  @Override
  public String getAssetName() {
    if (serviceAccount.getMetadata() != null) {
      return serviceAccount.getMetadata().getName();
    }
    return null;
  }

  @Override
  public String toString() {
    return String.format("ServiceAccount: %s", getAssetName());
  }

  @Override
  public ResourceType getResourceType() {
    return ResourceType.SERVICE_ACCOUNT;
  }

  /**
   * Returns the automountServiceAccountToken flag.
   * @return automountServiceAccountToken flag
   */
  public boolean getAutomountServiceAccountToken() {
    return BooleanUtils.isTrue(serviceAccount.getAutomountServiceAccountToken());
  }

}
