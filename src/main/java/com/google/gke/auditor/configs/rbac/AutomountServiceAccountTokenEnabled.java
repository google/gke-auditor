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

package com.google.gke.auditor.configs.rbac;

import com.google.gke.auditor.configs.KubernetesDetectorConfig;
import com.google.gke.auditor.models.Asset;
import com.google.gke.auditor.models.ServiceAccount;
import com.google.gke.auditor.system.ResourceType;
import java.util.List;

/**
 * A detector auditing the automounting of API credentials for a service account (CIS 5.1.6.).
 * <p>
 * Service accounts tokens should not be mounted in pods except where the workload running in the
 * pod explicitly needs to communicate with the API server.
 */
public final class AutomountServiceAccountTokenEnabled extends KubernetesDetectorConfig {

  @Override
  public String getDetectorName() {
    return "AUTOMOUNT_SERVICE_ACCOUNT_TOKENS_ENABLED";
  }

  @Override
  public ResourceType getAssetFilter() {
    return ResourceType.SERVICE_ACCOUNT;
  }

  @Override
  public Boolean isVulnerable(Asset asset) {
    ServiceAccount serviceAccount = getServiceAccount(asset);
    return serviceAccount.getAutomountServiceAccountToken();
  }

  @Override
  public String getExplanationText() {
    return "Service accounts tokens should not be mounted in pods except where the workload "
        + "running in the pod explicitly needs to communicate with the API server. Mounting "
        + "service account tokens inside pods can provide an avenue for privilege escalation attacks "
        + "where an attacker is able to compromise a single pod in the cluster. Avoiding mounting "
        + "these tokens removes this attack avenue.";
  }

  @Override
  public List<String> getUsefulURLs() {
    return List
        .of("https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/");
  }

  @Override
  public String getRecommendationText() {
    return "Modify the definition of pods and service accounts which do not need to "
        + "mount service account tokens to disable it.";
  }

  /**
   * Returns the asset as a {@link ServiceAccount}, or null if such conversion is not possible.
   * @param asset asset to convert
   * @return asset as a {@link ServiceAccount}
   */
  private ServiceAccount getServiceAccount(Asset asset) {
    if (asset instanceof ServiceAccount) {
      return (ServiceAccount) asset;
    }
    return null;
  }

}
