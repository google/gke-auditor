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

import com.google.gke.auditor.configs.KubernetesDetectorConfig;
import com.google.gke.auditor.models.Asset;
import com.google.gke.auditor.models.PodSecurityPolicy;
import com.google.gke.auditor.system.ResourceType;

/**
 * An abstract implementation of {@link KubernetesDetectorConfig}.
 * <p>
 * Provides default implementation methods shared by Pod Security Policy detectors. All Pod Security
 * Policy detectors should extend this class.
 */
public abstract class PodSecurityPolicyDetectorConfig extends KubernetesDetectorConfig {

  @Override
  public ResourceType getAssetFilter() {
    return ResourceType.POD_SECURITY_POLICY;
  }

  /**
   * Returns the asset as a {@link PodSecurityPolicy}, or null if such conversion is not possible.
   * @param asset asset to convert
   * @return asset as a {@link PodSecurityPolicy}
   */
  PodSecurityPolicy getPodSecurityPolicy(Asset asset) {
    if (asset instanceof PodSecurityPolicy) {
      return (PodSecurityPolicy) asset;
    }
    return null;
  }

  /**
   * Returns the formatted recommendation text for a Pod Security Policy detector:
   * <p>
   * If you have need to run containers which require $CONFIG, this should be defined in an separate
   * PSP and you should carefully check RBAC controls to ensure that only limited service accounts
   * and users are given permission to access that PSP.
   * @param config configuration to insert into the text
   * @return formatted recommendation text
   */
  String getRecommendationText(String config) {
    return String.format("If you have need to run containers which require %s, "
            + "this should be defined in an separate PSP and you should carefully check "
            + "RBAC controls to ensure that only limited service accounts and users are given "
            + "permission to access that PSP. ",
        config);
  }

  /**
   * Returns the formatted remediation text for a Pod Security Policy detector:
   * <p>
   * Create a PSP as described in the Kubernetes documentation, ensuring that the $PROPERTY field is
   * omitted or set to $VALUE."
   * @param property property to insert into remediation text template
   * @param value    value to insert into remediation text template
   * @return formatted remediation text
   */
  String getRemediationText(String property, String value) {
    return String.format("Create a PSP as described in the Kubernetes documentation, "
            + "ensuring that the %s field is omitted or set to %s.",
        property, value);
  }

  /**
   * Returns the Pod Security Policy documentation link.
   * @return psp documentation link
   */
  String getPSPDocumentationLink() {
    return "https://kubernetes.io/docs/concepts/policy/pod-security-policy/#enabling-pod-security-policies";
  }

}
