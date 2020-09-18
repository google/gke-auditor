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
import com.google.gke.auditor.configs.util.DetectorUtil;
import com.google.gke.auditor.configs.util.EscalatingResources;
import com.google.gke.auditor.models.Asset;
import com.google.gke.auditor.models.Dependency;
import com.google.gke.auditor.system.ResourceType;
import io.kubernetes.client.openapi.models.V1beta1PolicyRule;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A detector searching for over permissive Service Accounts.
 * <p>
 * Searches for a path from a Node to an Service Account with permissions on the Node and its
 * resources (Pods, Containers, Volume Mounts). Generates a dependency report if escalations are
 * found.
 */
public class EscalatingResourcesDependencyReport extends KubernetesDetectorConfig {

  @Override
  public String getDetectorName() {
    return "ESCALATING_RESOURCES_DEPENDENCY_REPORT";
  }

  @Override
  public ResourceType getAssetFilter() {
    return ResourceType.DEPENDENCY_REPORT;
  }

  @Override
  public Boolean isVulnerable(Asset asset) {
    Dependency dependency = getDependency(asset);
    List<V1beta1PolicyRule> escalatingRules = new ArrayList<>();
    if (dependency != null && dependency.getRole() != null && dependency.getRole().getRules() != null) {
      for (V1beta1PolicyRule rule : dependency.getRole().getRules()) {
        if (isEscalatingRule(rule)) {
          escalatingRules.add(rule);
        }
      }
      dependency.setEscalatingRules(escalatingRules);
    }
    return !escalatingRules.isEmpty();
  }

  /**
   * Checks if the given {@link V1beta1PolicyRule} is escalating.
   * @param rule rule to check if escalating
   * @return true if rule is escalating, false otherwise
   */
  private boolean isEscalatingRule(V1beta1PolicyRule rule) {
    List<String> apiGroupResources = DetectorUtil.getAPIGroupResources(rule);
    List<String> verbs = rule.getVerbs() == null ? Collections.emptyList() : rule.getVerbs();
    return hasEscalatingResources(apiGroupResources) ||
        hasEscalatingPrivilegesOnWrite(verbs, apiGroupResources) ||
        hasEscalatingSubresources(verbs, apiGroupResources);
  }

  /**
   * Checks if the given list of resources contains any escalating resources.
   * @param resources list of resources to check
   * @return true if the given list contains escalating resources, false otherwise
   */
  private boolean hasEscalatingResources(List<String> resources) {
    return !Collections.disjoint(resources, EscalatingResources.ESCALATING_RESOURCES);
  }

  /**
   * Checks if the given list of resources contains any escalating privileges on write.
   * @param verbs     list of verbs to check if escalating
   * @param resources list of resources to check if escalating
   * @return true if the given list contains escalating privileges on write, false otherwise
   */
  private boolean hasEscalatingPrivilegesOnWrite(List<String> verbs, List<String> resources) {
    if (Collections.disjoint(verbs, EscalatingResources.ESCALATING_VERBS)) {
      return false;
    }

    return !Collections.disjoint(resources,
        EscalatingResources.ESCALATING_RESOURCES_ON_WRITE);
  }

  /**
   * Checks if the given list of resources contains any escalating sub-resources.
   * @param verbs     list of verbs to check if escalating
   * @param resources list of resources to check if escalating
   * @return true if the given list contains escalating privileges on write, false otherwise
   */
  private boolean hasEscalatingSubresources(List<String> verbs, List<String> resources) {
    if (Collections.disjoint(verbs, EscalatingResources.ESCALATING_VERBS)) {
      return false;
    }

    for (String apiResource : resources) {
      int idx = apiResource.lastIndexOf("/");
      if (idx == -1) {
        continue;
      }
      String subResource = apiResource.substring(idx + 1);
      if (EscalatingResources.ESCALATING_SUBRESOURCES.contains(subResource)) {
        return true;
      }
    }
    return false;
  }

  @Override
  public String getExplanationText() {
    return "The dependency report searches for a path from a Node to a Service Account with "
        + "permissions on the Node and its resources (Pods, Containers, Volume Mounts). "
        + "There can be security implications if the Service Account is over permissive.";
  }

  @Override
  public List<String> getUsefulURLs() {
    return List
        .of("https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/");
  }

  @Override
  public String getRecommendationText() {
    return "Review on which resources the Service Account has permissions and remove the ones "
        + "that are not completely necessary.";
  }

  /**
   * Returns the asset as a {@link Dependency}, or null if such conversion is not possible.
   * @param asset asset to convert
   * @return asset as a {@link Dependency }
   */
  private Dependency getDependency(Asset asset) {
    if (asset instanceof Dependency) {
      return (Dependency) asset;
    }
    return null;
  }

}
