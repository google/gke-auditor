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
 * A detector auditing the admission of privileged containers (CIS 5.2.1.).
 * <p>
 * It is generally recommended to not permit privileged containers.
 */
public class PrivilegedContainers extends PodSecurityPolicyDetectorConfig {

  @Override
  public String getDetectorName() {
    return "PRIVILEGED_CONTAINERS";
  }

  @Override
  public Boolean isVulnerable(Asset asset) {
    PodSecurityPolicy psp = getPodSecurityPolicy(asset);
    boolean privileged = psp.getPrivileged();
    if (privileged) {
      psp.addMisconfiguration("Privileged", "true");
      return true;
    }
    return false;
  }

  @Override
  public String getExplanationText() {
    return "Privileged containers have access to all Linux Kernel capabilities and devices. "
        + "A container running with full privileges can do almost everything that the host can do. "
        + "This flag exists to allow special use-cases, like manipulating the network stack and "
        + "accessing devices. There should be at least one PodSecurityPolicy (PSP) defined which "
        + "does not permit privileged containers.";
  }

  @Override
  public List<String> getUsefulURLs() {
    return List
        .of(getPSPDocumentationLink(),
            "https://kubernetes.io/docs/concepts/policy/pod-security-policy/#privileged",
            "https://www.nccgroup.com/uk/our-research/abusing-privileged-and-unprivileged-linux-containers/");
  }

  @Override
  public String getRecommendationText() {
    return getRecommendationText("privileges") + getRemediationText(".spec.privileged", "false");
  }

}
