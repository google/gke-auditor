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
import com.google.gke.auditor.models.ClusterRoleBinding;
import com.google.gke.auditor.system.ResourceType;
import java.util.List;

/**
 * A detector auditing the usage of cluster-admin role (CIS 5.1.1.).
 * <p>
 * The RBAC role cluster-admin provides wide-ranging powers over the environment and should be used
 * only where and when needed.
 */
public class ClusterAdminRoleUsed extends KubernetesDetectorConfig {

  /**
   * Role name for cluster admin.
   */
  private static final String CLUSTER_ADMIN = "cluster-admin";

  @Override
  public String getDetectorName() {
    return "CLUSTER_ADMIN_ROLE_USED";
  }

  @Override
  public ResourceType getAssetFilter() {
    return ResourceType.CLUSTER_ROLE_BINDING;
  }

  @Override
  public Boolean isVulnerable(Asset asset) {
    ClusterRoleBinding clusterRoleBinding = getClusterRoleBinding(asset);
    return CLUSTER_ADMIN.equals(clusterRoleBinding.getRoleRefName());
  }

  @Override
  public String getExplanationText() {
    return "Kubernetes provides a set of default roles where RBAC is used. Some of these roles "
        + "such as cluster-admin provide wide-ranging privileges which should only be applied where "
        + "absolutely necessary. Roles such as cluster-admin allow super-user access to perform any "
        + "action on any resource. When used in a ClusterRoleBinding, it gives full control over "
        + "every resource in the cluster and in all namespaces. When used in a RoleBinding, it gives "
        + "full control over every resource in the RoleBinding's namespace, including the namespace "
        + "itself.";
  }

  @Override
  public List<String> getUsefulURLs() {
    return List.of("https://kubernetes.io/docs/admin/authorization/rbac/#user-facing-roles");
  }

  @Override
  public String getRecommendationText() {
    return "Identify all ClusterRoleBindings to the cluster-admin role. Check if they are used and "
        + "if they need this role or if they could use a role with fewer privileges. Where possible, "
        + "first bind users to a lower privileged role and then remove the clusterrolebinding to the "
        + "cluster-admin role. Care should be taken before removing any clusterrolebindings from "
        + "the environment to ensure they were not required for operation of the cluster. Specifically, "
        + "modifications should not be made to clusterrolebindings with the system: prefix as they "
        + "are required for the operation of system components.";
  }

  /**
   * Returns the asset as a {@link ClusterRoleBinding}, or null if such conversion is not possible.
   * @param asset asset to convert
   * @return asset as a {@link ClusterRoleBinding}
   */
  private ClusterRoleBinding getClusterRoleBinding(Asset asset) {
    if (asset instanceof ClusterRoleBinding) {
      return (ClusterRoleBinding) asset;
    }
    return null;
  }

}
