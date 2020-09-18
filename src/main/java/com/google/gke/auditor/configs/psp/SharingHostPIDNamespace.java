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
 * A detector auditing the admission of containers wishing to share the host process ID namespace
 * (CIS 5.2.2.).
 * <p>
 * It is generally recommended to not permit containers with the hostPID flag set to true.
 */
public class SharingHostPIDNamespace extends PodSecurityPolicyDetectorConfig {

  @Override
  public String getDetectorName() {
    return "CONTAINERS_SHARING_HOST_PROCESS_ID_NAMESPACE";
  }

  @Override
  public Boolean isVulnerable(Asset asset) {
    PodSecurityPolicy psp = getPodSecurityPolicy(asset);
    boolean hostPID = psp.getHostPID();
    if (hostPID) {
      psp.addMisconfiguration("HostPID", "true");
      return true;
    }
    return false;
  }

  @Override
  public String getExplanationText() {
    return "A container running in the host's PID namespace can inspect processes running outside "
        + "the container. If the container also has access to ptrace capabilities this can be used to "
        + "escalate privileges outside of the container. There should be at least one PodSecurityPolicy "
        + "(PSP) defined which does not permit containers to share the host PID namespace.";
  }

  @Override
  public List<String> getUsefulURLs() {
    return List
        .of(getPSPDocumentationLink(),
            "https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces");
  }

  @Override
  public String getRecommendationText() {
    return getRecommendationText("hostPID") + getRemediationText(".spec.hostPID", "false");
  }

}
