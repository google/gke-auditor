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
import io.kubernetes.client.openapi.models.PolicyV1beta1IDRange;
import io.kubernetes.client.openapi.models.PolicyV1beta1RunAsUserStrategyOptions;
import java.util.List;

/**
 * A detector auditing the admission of containers run as the root users (CIS 5.2.6.).
 * <p>
 * It is generally recommended to not permit containers to be run as root.
 */
public class RootContainersAdmission extends PodSecurityPolicyDetectorConfig {

  @Override
  public String getDetectorName() {
    return "ROOT_CONTAINERS_ADMISSION";
  }

  /**
   * Verifies that there is at least one PSP which returns MustRunAsNonRoot or MustRunAs with the
   * range of UIDs not including 0.
   * @param asset asset to audit
   * @return true if asset is vulnerable, false otherwise
   */
  @Override
  public Boolean isVulnerable(Asset asset) {
    PodSecurityPolicy psp = getPodSecurityPolicy(asset);
    PolicyV1beta1RunAsUserStrategyOptions policy = psp.getRunAsUser();
    if (policy != null
        && !(policy.getRule().equals("MustRunAsNonRoot")
        || policy.getRule().equals("MustRunAs") && validateMustRunAs(policy))) {
      psp.addRunAsUserMisconfigurationToRepresentation();
      return true;
    }
    return false;
  }

  /**
   * Validated the {@link PolicyV1beta1RunAsUserStrategyOptions} MustRunAs policy to ensure
   * containers are not permitted to be run as root.
   * <p>
   * The policy must not include 0 in its range of UIDs.
   * @param policy policy to check
   * @return true if the policy does not allow containers to be run as root, false otherwise
   */
  private boolean validateMustRunAs(PolicyV1beta1RunAsUserStrategyOptions policy) {
    if (policy.getRanges() != null) {
      for (PolicyV1beta1IDRange range : policy.getRanges()) {
        if (range.getMin() == 0) {
          return false;
        }
      }
    }
    return true;
  }

  @Override
  public String getExplanationText() {
    return "Containers may run as any Linux user. Containers which run as the root user, whilst "
        + "constrained by Container Runtime security features still have an escalated likelihood of "
        + "container breakout. Ideally, all containers should run as a defined non-UID 0 user. "
        + "There should be at least one PodSecurityPolicy (PSP) defined which does not permit root "
        + "users in a container.";
  }

  @Override
  public List<String> getUsefulURLs() {
    return List
        .of(getPSPDocumentationLink(),
            "https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems",
            "https://kubernetes.io/docs/concepts/policy/pod-security-policy/#users-and-groups");
  }

  @Override
  public String getRecommendationText() {
    return getRecommendationText("root containers") + getRemediationText("spec.runAsUser.rule",
        "either MustRunAsNonRoot or MustRunAs with the range of UIDs not including 0");
  }

}
