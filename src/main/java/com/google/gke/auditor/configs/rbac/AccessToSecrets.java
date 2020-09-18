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
import com.google.gke.auditor.models.KubernetesRole;
import com.google.gke.auditor.system.ResourceType;
import io.kubernetes.client.openapi.models.V1beta1PolicyRule;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

/**
 * A detector auditing roles permitting access to secrets. (CIS 5.1.2.). Access to secrets should be
 * restricted.
 */
public class AccessToSecrets extends KubernetesDetectorConfig {

  /**
   * Set of escalating verbs.
   */
  private static final HashSet<String> ESCALATING_VERBS = new HashSet<>(
      List.of("get", "list", "watch"));
  /**
   * The secrets resource.
   */
  private static final String SECRET = "secrets";

  @Override
  public String getDetectorName() {
    return "ACCESS_TO_SECRETS";
  }

  @Override
  public ResourceType[] getAssetFilters() {
    return new ResourceType[]{ResourceType.CLUSTER_ROLE, ResourceType.ROLE};
  }

  @Override
  public Boolean isVulnerable(Asset asset) {
    KubernetesRole role = getKubernetesRole(asset);
    List<V1beta1PolicyRule> rules = role.getRules();

    List<V1beta1PolicyRule> vulnerableRules = new ArrayList<>();
    for (V1beta1PolicyRule rule : rules) {
      if (hasSecrets(rule.getResources()) && hasEscalatingVerbs(rule.getVerbs())) {
        vulnerableRules.add(rule);
      }
    }
    role.addVulnerableRules(vulnerableRules);
    return !vulnerableRules.isEmpty();
  }

  /**
   * Checks if the given list of resources contains "secrets" resource.
   * @param resources list of resources to check
   * @return true if the given list contains "secrets", false otherwise
   */
  private boolean hasSecrets(List<String> resources) {
    return resources != null && resources.contains(SECRET);
  }

  /**
   * Checks if the given list of verbs contains escalating verbs.
   * @param verbs list of verbs to check
   * @return true if the given list contains any escalating verbs, false otherwise
   */
  private boolean hasEscalatingVerbs(List<String> verbs) {
    return verbs != null && !Collections.disjoint(verbs, ESCALATING_VERBS);
  }

  @Override
  public String getExplanationText() {
    return "The Kubernetes API stores secrets, which may be service account tokens for the "
        + "Kubernetes API or credentials used by workloads in the cluster. Access to these secrets "
        + "should be restricted to the smallest possible group of users to reduce the risk of "
        + "privilege escalation. Inappropriate access to secrets stored within the Kubernetes "
        + "cluster can allow for an attacker to gain additional access to the Kubernetes cluster "
        + "or external resources whose credentials are stored as secrets.";
  }

  @Override
  public String getRecommendationText() {
    return "Review the users who have get, list or watch access to secrets objects in the "
        + "Kubernetes API. Where possible, remove access. Care should be taken not to remove "
        + "access to secrets to system components which require this for their operation.";
  }

  @Override
  public List<String> getUsefulURLs() {
    return List.of("https://kubernetes.io/docs/concepts/configuration/secret/");
  }

  /**
   * Returns the asset as a {@link KubernetesRole}, or null if such conversion is not possible.
   * @param asset asset to convert
   * @return asset as a {@link KubernetesRole}
   */
  private KubernetesRole getKubernetesRole(Asset asset) {
    if (asset instanceof KubernetesRole) {
      return (KubernetesRole) asset;
    }
    return null;
  }

}
