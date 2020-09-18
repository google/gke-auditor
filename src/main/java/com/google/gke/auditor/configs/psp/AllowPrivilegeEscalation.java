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
 * A detector auditing the admission of containers with allowPrivilegeEscalation (CIS 5.2.5.).
 * <p>
 * It is generally recommended to not permit containers to allowPrivilegeEscalation.
 */
public class AllowPrivilegeEscalation extends PodSecurityPolicyDetectorConfig {

  @Override
  public String getDetectorName() {
    return "CONTAINER_ALLOW_PRIVILEGE_ESCALATION";
  }

  @Override
  public Boolean isVulnerable(Asset asset) {
    PodSecurityPolicy psp = getPodSecurityPolicy(asset);
    boolean allowPrivilegeEscalation = psp.getAllowPrivilegeEscalation();
    if (allowPrivilegeEscalation) {
      psp.addMisconfiguration("AllowPrivilegeEscalation", "true");
      return true;
    }
    return false;
  }

  @Override
  public String getExplanationText() {
    return "A container running with the allowPrivilegeEscalation flag set to true may have "
        + "processes that can gain more privileges than their parent. There should be at least one "
        + "PodSecurityPolicy (PSP) defined which does not permit containers to allow privilege "
        + "escalation. The option exists (and is defaulted to true) to permit setuid binaries to run.";
  }

  @Override
  public List<String> getUsefulURLs() {
    return List
        .of(getPSPDocumentationLink(),
            "https://kubernetes.io/docs/concepts/policy/pod-security-policy/#privilege-escalation");
  }

  @Override
  public String getRecommendationText() {
    return getRecommendationText("setuid binaries or require privilege escalation")
        + getRemediationText(".spec.allowPrivilegeEscalation", "false");
  }

}
