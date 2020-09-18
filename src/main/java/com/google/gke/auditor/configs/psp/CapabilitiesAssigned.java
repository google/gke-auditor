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

package com.google.gke.auditor.configs.psp;

import com.google.gke.auditor.models.Asset;
import com.google.gke.auditor.models.PodSecurityPolicy;
import java.util.List;

/**
 * A detector auditing the admission of containers with capabilities assigned (CIS 5.2.9.).
 * <p>
 * It is generally recommended to not permit containers with capabilities.
 */
public class CapabilitiesAssigned extends PodSecurityPolicyDetectorConfig {

  @Override
  public String getDetectorName() {
    return "CONTAINERS_CAPABILITIES_ASSIGNED";
  }

  @Override
  public Boolean isVulnerable(Asset asset) {
    PodSecurityPolicy psp = getPodSecurityPolicy(asset);
    List<String> requiredDropCapabilities = psp.getRequiredDropCapabilities();
    if (requiredDropCapabilities != null && requiredDropCapabilities.contains("ALL")) {
      return false;
    }

    psp.addMisconfiguration("Required Drop Capabilities",
        requiredDropCapabilities == null ? "[]" : requiredDropCapabilities.toString());
    return true;
  }

  @Override
  public String getExplanationText() {
    return "Containers run with a default set of capabilities as assigned by the Container "
        + "Runtime. Capabilities are parts of the rights generally granted on a Linux system to "
        + "the root user. In many cases applications running in containers do not require any "
        + "capabilities to operate, so from the perspective of the principal of least privilege use "
        + "of capabilities should be minimized.";
  }

  @Override
  public List<String> getUsefulURLs() {
    return List
        .of(getPSPDocumentationLink(),
            "https://kubernetes.io/docs/concepts/policy/pod-security-policy/#capabilities");
  }

  @Override
  public String getRecommendationText() {
    return "Review the use of capabilities in applications running on your cluster. Where a "
        + "namespace contains applications which do not require any Linux capabilities to operate "
        + "consider adding a PSP which forbids the admission of containers which do not drop all "
        + "capabilities.";
  }

}
