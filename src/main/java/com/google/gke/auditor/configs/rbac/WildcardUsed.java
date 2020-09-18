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
 * A detector auditing the usage of wildcards in roles (CIS 5.1.3.).
 * <p>
 * Use of wildcards is not optimal from a security perspective as it may allow for inadvertent
 * access to be granted when new resources are added to the Kubernetes API either as CRDs or in
 * later versions of the product.
 */
public class WildcardUsed extends KubernetesDetectorConfig {

  /**
   * Wildcard resource.
   */
  private final static String WILDCARD = "*";

  @Override
  public String getDetectorName() {
    return "WILDCARD_USED";
  }

  @Override
  public ResourceType[] getAssetFilters() {
    return new ResourceType[]{ResourceType.ROLE, ResourceType.CLUSTER_ROLE};
  }

  @Override
  public Boolean isVulnerable(Asset asset) {
    KubernetesRole role = getKubernetesRole(asset);

    List<V1beta1PolicyRule> vulnerableRules = new ArrayList<>();
    for (V1beta1PolicyRule rule : role.getRules()) {
      if (checkForWildcard(rule.getApiGroups())
          || checkForWildcard(rule.getResources())
          || checkForWildcard(rule.getVerbs())
          || checkForWildcard(rule.getNonResourceURLs())
          || checkForWildcard(rule.getResourceNames())) {
        vulnerableRules.add(rule);
      }
    }
    role.addVulnerableRules(vulnerableRules);
    return !vulnerableRules.isEmpty();
  }

  /**
   * Checks if the given list of verbs contains the wildcard (*) resource.
   * @param resources list of resources to check
   * @return true if the given list contains wildcards, false otherwise
   */
  private boolean checkForWildcard(List<String> resources) {
    return resources != null && resources.contains(WILDCARD);
  }

  @Override
  public List<String> getUsefulURLs() {
    return List.of("https://kubernetes.io/docs/admin/authorization/rbac");
  }

  @Override
  public String getExplanationText() {
    return "Kubernetes Roles and ClusterRoles provide access to resources based on sets of objects "
        + "and actions that can be taken on those objects. It is possible to set either of these to be "
        + "the wildcard \"*\" which matches all items. Use of wildcards is not optimal from a security "
        + "perspective as it may allow for inadvertent access to be granted when new resources are "
        + "added to the Kubernetes API either as CRDs or in later versions of the product. The "
        + "principle of least privilege recommends that users are provided only the access required "
        + "for their role and nothing more. The use of wildcard rights grants is likely to provide "
        + "excessive rights to the Kubernetes API.";
  }

  @Override
  public String getRecommendationText() {
    return "Where possible replace any use of wildcards in clusterroles and roles with specific objects or actions.";
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
