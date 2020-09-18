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
 * A detector auditing the admission of containers with the NET_RAW capability (CIS 5.2.7.).
 * <p>
 * It is generally recommended to not permit containers with the potentially dangerous NET_RAW
 * capability.
 */
public class NetRawCapabilities extends PodSecurityPolicyDetectorConfig {

  @Override
  public String getDetectorName() {
    return "CONTAINERS_NET_RAW_CAPABILITIES";
  }

  @Override
  public Boolean isVulnerable(Asset asset) {
    PodSecurityPolicy psp = getPodSecurityPolicy(asset);
    List<String> requiredDropCapabilities = psp.getRequiredDropCapabilities();
    if (requiredDropCapabilities != null
        && !requiredDropCapabilities.contains("ALL")
        && !requiredDropCapabilities.contains("NET_RAW")) {
      psp.addMisconfiguration("Required Drop Capabilities", requiredDropCapabilities.toString());
      return true;
    }
    return false;
  }

  @Override
  public String getExplanationText() {
    return "Containers run with a default set of capabilities as assigned by the Container "
        + "Runtime. By default, this can include potentially dangerous capabilities. With Docker as "
        + "the container runtime the NET_RAW capability is enabled which may be misused by malicious "
        + "containers. Ideally, all containers should drop this capability. There should be at least "
        + "one PodSecurityPolicy (PSP) defined which prevents containers with the NET_RAW capability "
        + "from launching.";
  }

  @Override
  public List<String> getUsefulURLs() {
    return List
        .of(getPSPDocumentationLink(),
            "https://kubernetes.io/docs/concepts/policy/pod-security-policy/#capabilities");
  }

  @Override
  public String getRecommendationText() {
    return getRecommendationText("NET_RAW capability") + getRemediationText(
        ".spec.requiredDropCapabilities", "either NET_RAW or ALL");
  }

}
