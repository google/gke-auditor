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
import io.kubernetes.client.openapi.models.PolicyV1beta1IDRange;
import io.kubernetes.client.openapi.models.PolicyV1beta1PodSecurityPolicy;
import io.kubernetes.client.openapi.models.PolicyV1beta1PodSecurityPolicySpec;
import io.kubernetes.client.openapi.models.PolicyV1beta1RunAsUserStrategyOptions;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;

/**
 * A wrapper class around {@link PolicyV1beta1PodSecurityPolicy}.
 */
public class PodSecurityPolicy extends Asset {

  /**
   * API Pod Security Policy reference.
   */
  private final PolicyV1beta1PodSecurityPolicy podSecurityPolicy;
  /**
   * A collection of found misconfigurations by the tool in the format of key-value pairs where the
   * key denotes the vulnerable property of the PSP.
   */
  private final Map<String, String> misconfigurations = new HashMap<>();

  /**
   * Initialize the PSP.
   * @param podSecurityPolicy podSecurityPolicy
   */
  public PodSecurityPolicy(PolicyV1beta1PodSecurityPolicy podSecurityPolicy) {
    this.podSecurityPolicy = podSecurityPolicy;
  }

  /**
   * Adds a found misconfiguration to the collection of PSP misconfigurations.
   * @param key   property of the PSP found to be misconfigured
   * @param value value of the PSP property found to be misconfigured
   */
  public void addMisconfiguration(String key, String value) {
    misconfigurations.put(key, value);
  }

  @Override
  public Logger.Builder getReport() {
    Logger.Builder builder = Logger.builder();
    builder.addMessage("Pod Security Policy", getAssetName(), Color.RED);
    for (Entry<String, String> entry : misconfigurations.entrySet()) {
      builder.addSubMessage(entry.getKey(), entry.getValue(), Color.RED);
    }
    builder.addSubMessageLineBreak();
    misconfigurations.clear();
    return builder;
  }

  @Override
  public String toString() {
    return String.format("Pod Security Policy: %s", getAssetName());
  }

  @Override
  public String getAssetName() {
    if (podSecurityPolicy.getMetadata() != null) {
      return podSecurityPolicy.getMetadata().getName();
    }
    return null;
  }

  @Override
  public ResourceType getResourceType() {
    return ResourceType.POD_SECURITY_POLICY;
  }

  /**
   * Returns the PSP {@link PolicyV1beta1PodSecurityPolicySpec}.
   * @return PSP spec
   */
  private Optional<PolicyV1beta1PodSecurityPolicySpec> getSpec() {
    return Optional.ofNullable(podSecurityPolicy)
        .map(PolicyV1beta1PodSecurityPolicy::getSpec);
  }

  /**
   * Returns a list of PSP allowed capabilities, or an empty list if there is none.
   * @return list of allowed capabilities
   */
  public List<String> getAllowedCapabilities() {
    return getSpec().map(PolicyV1beta1PodSecurityPolicySpec::getAllowedCapabilities)
        .orElse(Collections.emptyList());
  }

  /**
   * Returns the PSP allowPrivilegeEscalation flag.
   * @return allowPrivilegeEscalation flag
   */
  public boolean getAllowPrivilegeEscalation() {
    return getSpec().map(PolicyV1beta1PodSecurityPolicySpec::getAllowPrivilegeEscalation)
        .orElse(false);
  }

  /**
   * Returns a list of PSP required drop capabilities, or an empty list if there is none.
   * @return list of required drop capabilities
   */
  public List<String> getRequiredDropCapabilities() {
    return getSpec().map(PolicyV1beta1PodSecurityPolicySpec::getRequiredDropCapabilities)
        .orElse(Collections.emptyList());
  }

  /**
   * Returns the PSP privileged flag.
   * @return privileged flag
   */
  public boolean getPrivileged() {
    return getSpec().map(PolicyV1beta1PodSecurityPolicySpec::getPrivileged).orElse(false);
  }

  /**
   * Returns the PSP {@link PolicyV1beta1RunAsUserStrategyOptions}.
   * @return {@link PolicyV1beta1RunAsUserStrategyOptions}
   */
  public PolicyV1beta1RunAsUserStrategyOptions getRunAsUser() {
    return getSpec().map(PolicyV1beta1PodSecurityPolicySpec::getRunAsUser).orElse(null);
  }

  /**
   * Returns the PSP hostIPC flag.
   * @return hostIPC flag
   */
  public boolean getHostIPC() {
    return getSpec().map(PolicyV1beta1PodSecurityPolicySpec::getHostIPC).orElse(false);
  }

  /**
   * Returns the PSP hostNetwork flag.
   * @return hostNetwork flag
   */
  public boolean getHostNetwork() {
    return getSpec().map(PolicyV1beta1PodSecurityPolicySpec::getHostNetwork).orElse(false);
  }

  /**
   * Returns the PSP hostPID flag.
   * @return hostPID flag
   */
  public boolean getHostPID() {
    return getSpec().map(PolicyV1beta1PodSecurityPolicySpec::getHostPID).orElse(false);
  }

  /**
   * Formats the misconfigured {@link PolicyV1beta1RunAsUserStrategyOptions} and adds it to the
   * collection of misconfigurations in a suitable format.
   */
  public void addRunAsUserMisconfigurationToRepresentation() {
    StringBuilder sb = new StringBuilder();
    PolicyV1beta1RunAsUserStrategyOptions runAsUser = getRunAsUser();
    if (getRunAsUser() != null) {
      sb.append(getRunAsUser().getRule());

      if (runAsUser.getRanges() != null) {
        for (PolicyV1beta1IDRange range : runAsUser.getRanges()) {
          sb.append(" [").append(range.getMin()).append(",").append(range.getMax()).append("]");
        }
      }
    }
    misconfigurations.put("RunAs", sb.toString());
  }

}
