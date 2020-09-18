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
import java.util.List;

/**
 * A detector auditing the access to create pods (CIS 5.1.4.).
 * <p>
 * Access to create new pods should be restricted to the smallest possible group of users.
 */
public class CreatePodsAllowed extends KubernetesDetectorConfig {

  /**
   * Create verb.
   */
  private static final String CREATE = "create";
  /**
   * Pod resource name.
   */
  private static final String PODS = "pods";

  @Override
  public String getDetectorName() {
    return "CREATE_PODS_ALLOWED";
  }

  @Override
  public ResourceType[] getAssetFilters() {
    return new ResourceType[]{ResourceType.CLUSTER_ROLE, ResourceType.ROLE};
  }

  @Override
  public Boolean isVulnerable(Asset asset) {
    KubernetesRole role = getKubernetesRole(asset);

    List<V1beta1PolicyRule> vulnerableRules = new ArrayList<>();
    for (V1beta1PolicyRule rule : role.getRules()) {
      if (hasPodResource(rule.getResources()) && hasCreateAccess(rule.getVerbs())) {
        vulnerableRules.add(rule);
      }
    }
    role.addVulnerableRules(vulnerableRules);
    return !vulnerableRules.isEmpty();
  }

  /**
   * Checks if the given list of verbs contains the "pods" resource.
   * @param resources list of resources to check
   * @return true if the given list contains pods, false otherwise
   */
  private boolean hasPodResource(List<String> resources) {
    return resources != null && resources.contains(PODS);
  }

  /**
   * Checks if the given list of verbs contains the "create" verb.
   * @param verbs list of verbs to check
   * @return true if the given list contains "create", false otherwise
   */
  private boolean hasCreateAccess(List<String> verbs) {
    return verbs != null && verbs.contains(CREATE);
  }

  @Override
  public String getExplanationText() {
    return "The ability to create pods in a namespace can provide a number of opportunities for "
        + "privilege escalation, such as assigning privileged service accounts to these pods or "
        + "mounting hostPaths with access to sensitive data (unless Pod Security Policies are "
        + "implemented to restrict this access. As such, access to create new pods should be "
        + "restricted to the smallest possible group of users. The ability to create pods in a "
        + "cluster opens up possibilities for privilege escalation and should be restricted, "
        + "where possible.";
  }

  @Override
  public List<String> getUsefulURLs() {
    return List.of("https://kubernetes.io/docs/admin/authorization/rbac");
  }

  @Override
  public String getRecommendationText() {
    return "Review the users who have create access to pod objects in the Kubernetes API. "
        + "Where possible, remove create access to pod objects in the cluster. "
        + "Care should be taken not to remove access to pods to system components "
        + "which require this for their operation.";
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
