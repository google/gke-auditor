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
 * A detector auditing the admission of containers with added capabilities. (CIS 5.2.8.)
 * <p>
 * It is generally not recommended to permit containers with capabilities assigned beyond the
 * default set.
 */
public class AddedCapabilities extends PodSecurityPolicyDetectorConfig {

  @Override
  public String getDetectorName() {
    return "CONTAINERS_ADDED_CAPABILITIES";
  }

  @Override
  public Boolean isVulnerable(Asset asset) {
    PodSecurityPolicy psp = getPodSecurityPolicy(asset);
    List<String> allowedCapabilities = psp.getAllowedCapabilities();
    if (allowedCapabilities != null && !allowedCapabilities.isEmpty()) {
      psp.addMisconfiguration("Allowed capabilities", allowedCapabilities.toString());
      return true;
    }

    return false;
  }

  @Override
  public String getExplanationText() {
    return "Containers run with a default set of capabilities as assigned by the Container Runtime."
        + "Capabilities outside this set can be added to containers which could expose them to "
        + "risks of container breakout attacks. There should be at least one PodSecurityPolicy (PSP) "
        + "defined which prevents containers with capabilities beyond the default set from launching.";
  }

  @Override
  public List<String> getUsefulURLs() {
    return List
        .of(getPSPDocumentationLink(),
            "https://kubernetes.io/docs/concepts/policy/pod-security-policy/#capabilities");
  }

  @Override
  public String getRecommendationText() {
    return getRecommendationText("additional capabilities")
        + "Ensure that allowedCapabilities is not present in PSPs for the cluster unless it is set to an empty array.";
  }

}
