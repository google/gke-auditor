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

package com.google.gke.auditor.system;

import com.google.common.annotations.VisibleForTesting;
import com.google.gke.auditor.configs.util.DetectorUtil;
import com.google.gke.auditor.models.Asset;
import com.google.gke.auditor.models.ClusterRole;
import com.google.gke.auditor.models.ClusterRoleBinding;
import com.google.gke.auditor.models.Dependency;
import com.google.gke.auditor.models.KubernetesRole;
import com.google.gke.auditor.models.KubernetesRoleBinding;
import com.google.gke.auditor.models.Node;
import com.google.gke.auditor.models.NodePodBinding;
import com.google.gke.auditor.models.Pod;
import com.google.gke.auditor.models.PodSecurityPolicy;
import com.google.gke.auditor.models.Role;
import com.google.gke.auditor.models.RoleBinding;
import com.google.gke.auditor.models.ServiceAccount;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.Configuration;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.apis.PolicyV1beta1Api;
import io.kubernetes.client.openapi.apis.RbacAuthorizationV1beta1Api;
import io.kubernetes.client.openapi.models.PolicyV1beta1PodSecurityPolicyList;
import io.kubernetes.client.openapi.models.V1NodeList;
import io.kubernetes.client.openapi.models.V1PodList;
import io.kubernetes.client.openapi.models.V1ServiceAccountList;
import io.kubernetes.client.openapi.models.V1beta1ClusterRoleBindingList;
import io.kubernetes.client.openapi.models.V1beta1ClusterRoleList;
import io.kubernetes.client.openapi.models.V1beta1RoleBindingList;
import io.kubernetes.client.openapi.models.V1beta1RoleList;
import io.kubernetes.client.openapi.models.V1beta1Subject;
import io.kubernetes.client.util.Config;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

/**
 * A service class used to communicate with the K8s APIs.
 */
public class AssetService {

  /**
   * A cache of resources.
   */
  private static final HashMap<ResourceType, List<Asset>> resources = new HashMap<>();
  /**
   * A cache of functions that can be used to fetch a resource of a specific type.
   */
  private static final HashMap<ResourceType, ResourceFetchFunction> resourceFetchFunctions = new HashMap<>();

  static ApiClient client;

  /**
   * Core api.
   */
  private static CoreV1Api api;
  /**
   * RBAC api.
   */

  private static RbacAuthorizationV1beta1Api rbacApi;
  /**
   * Policy api.
   */
  private static PolicyV1beta1Api policyApi;

  /**
   * If true, includes the default K8s assets to the assets being fetched.
   */
  private static boolean includeDefaults;

  static {
    try {
      client = Config.defaultClient();
      Configuration.setDefaultApiClient(client);

      api = new CoreV1Api();
      rbacApi = new RbacAuthorizationV1beta1Api();
      policyApi = new PolicyV1beta1Api();

      initResourceFetchFunctionMap();
    } catch (IllegalStateException | ExceptionInInitializerError e) {
      Logger.logError("Invalid authorization for communication with the API.");
      System.exit(0);
    } catch (IOException e) {
      Logger.logError("An exception occurred while communicating with the API.");
      System.exit(0);
    }
  }

  /**
   * Initializes the asset service.
   * @param defaults if true, default K8s assets are included in the lists of assets returned
   */
  public static void init(boolean defaults) {
    includeDefaults = defaults;
    try {
      client = Config.defaultClient();
      Configuration.setDefaultApiClient(client);

      api = new CoreV1Api();
      rbacApi = new RbacAuthorizationV1beta1Api();
      policyApi = new PolicyV1beta1Api();

      initResourceFetchFunctionMap();
    } catch (IllegalStateException | ExceptionInInitializerError e) {
      Logger.logError("Invalid authorization for communication with the API.");
      System.exit(0);
    } catch (IOException e) {
      Logger.logError("An exception occurred while communicating with the API.");
      System.exit(0);
    }
  }

  /**
   * Initializes the resource fetch functions cache.
   */
  @VisibleForTesting
  static void initResourceFetchFunctionMap() {
    resourceFetchFunctions.put(ResourceType.NODE, AssetService::fetchNodes);
    resourceFetchFunctions.put(ResourceType.POD, AssetService::fetchPods);
    resourceFetchFunctions
        .put(ResourceType.NODE_POD_BINDING, AssetService::generateNodePodBindings);
    resourceFetchFunctions.put(ResourceType.SERVICE_ACCOUNT, AssetService::fetchServiceAccounts);
    resourceFetchFunctions
        .put(ResourceType.CLUSTER_ROLE_BINDING, AssetService::fetchClusterRoleBindings);
    resourceFetchFunctions.put(ResourceType.CLUSTER_ROLE, AssetService::fetchClusterRoles);
    resourceFetchFunctions.put(ResourceType.ROLE, AssetService::fetchRoles);
    resourceFetchFunctions.put(ResourceType.ROLE_BINDING, AssetService::fetchRoleBindings);
    resourceFetchFunctions
        .put(ResourceType.DEPENDENCY_REPORT, AssetService::generateDependencies);
    resourceFetchFunctions
        .put(ResourceType.POD_SECURITY_POLICY, AssetService::fetchPodSecurityPolicies);

  }

  /**
   * Retrieves the cache of resources.
   * @return cache of resources
   */
  @VisibleForTesting
  static HashMap<ResourceType, List<Asset>> getResources() {
    return resources;
  }

  /**
   * Fetches service accounts from the api and stores them in the resource cache.
   * @throws ApiException in case of API communication error
   */
  private static void fetchServiceAccounts() throws ApiException {
    V1ServiceAccountList serviceAccounts = api.listServiceAccountForAllNamespaces(false, null,
        null, null, null, null, null, null, null);

    resources.put(ResourceType.SERVICE_ACCOUNT,
        serviceAccounts.getItems().stream()
            .map(ServiceAccount::new)
            .collect(Collectors.toList()));
  }

  /**
   * Fetches nodes from the api and stores them in the resource cache.
   * @throws ApiException in case of API communication error
   */
  private static void fetchNodes() throws ApiException {
    V1NodeList nodes = api.listNode(null, null, null,
        null, null, null,
        null, null, null);

    resources.put(ResourceType.NODE,
        nodes.getItems().stream().map(Node::new).collect(Collectors.toList()));
  }

  /**
   * Fetches pods from the api and stores them in the resource cache.
   * @throws ApiException in case of API communication error
   */
  private static void fetchPods() throws ApiException {
    V1PodList pods = api.listPodForAllNamespaces(null, null, null,
        null, null, null,
        null, null, null);

    resources.put(ResourceType.POD,
        pods.getItems().stream().map(Pod::new).collect(Collectors.toList()));
  }

  /**
   * Generates {@link NodePodBinding}s.
   */
  private static void generateNodePodBindings() {
    List<Asset> nodePodBindings = new ArrayList<>();
    for (Asset node : getAssets(ResourceType.NODE)) {
      for (Asset pod : getAssets(ResourceType.POD)) {
        nodePodBindings.add(new NodePodBinding((Node) node, (Pod) pod));
      }
    }
    resources.put(ResourceType.NODE_POD_BINDING, nodePodBindings);
  }

  /**
   * Fetches cluster role bindings from the api and stores them in the resource cache.
   * @throws ApiException in case of API communication error
   */
  private static void fetchClusterRoleBindings() throws ApiException {
    V1beta1ClusterRoleBindingList clusterRoleBindings = rbacApi
        .listClusterRoleBinding(null, null, null,
            null, null, null,
            null, null, null);

    resources.put(ResourceType.CLUSTER_ROLE_BINDING,
        clusterRoleBindings.getItems().stream()
            .map(ClusterRoleBinding::new)
            .collect(Collectors.toList()));
  }

  /**
   * Fetches cluster roles from the api and stores them in the resource cache.
   * @throws ApiException in case of API communication error
   */
  private static void fetchClusterRoles() throws ApiException {
    V1beta1ClusterRoleList clusterRoles = rbacApi.listClusterRole(null, null, null,
        null, null, null,
        null, null, null);

    resources.put(ResourceType.CLUSTER_ROLE,
        clusterRoles.getItems().stream()
            .map(ClusterRole::new)
            .collect(Collectors.toList()));
  }

  /**
   * Fetches roles from the api and stores them in the resource cache.
   * @throws ApiException in case of API communication error
   */
  private static void fetchRoles() throws ApiException {
    V1beta1RoleList roles = rbacApi.listRoleForAllNamespaces(null, null, null,
        null, null, null,
        null, null, null);

    resources.put(ResourceType.ROLE,
        roles.getItems().stream()
            .map(Role::new)
            .collect(Collectors.toList()));
  }

  /**
   * Fetches role bindings from the api and stores them in the resource cache.
   * @throws ApiException in case of API communication error
   */
  private static void fetchRoleBindings() throws ApiException {
    V1beta1RoleBindingList roles = rbacApi.listRoleBindingForAllNamespaces(null, null, null,
        null, null, null,
        null, null, null);

    resources.put(ResourceType.ROLE_BINDING,
        roles.getItems().stream()
            .map(RoleBinding::new)
            .collect(Collectors.toList()));
  }

  /**
   * Generates Dependencies.
   */
  private static void generateDependencies() {
    List<Asset> nodes = getAssets(ResourceType.NODE);
    List<Asset> pods = getAssets(ResourceType.POD);

    List<Asset> clusterRoleBindings = getAssets(ResourceType.CLUSTER_ROLE_BINDING);
    List<Asset> clusterRoles = getAssets(ResourceType.CLUSTER_ROLE);
    List<Asset> roleBindings = getAssets(ResourceType.ROLE_BINDING);
    List<Asset> roles = getAssets(ResourceType.ROLE);

    List<Asset> dependencies = new ArrayList<>();
    dependencies.addAll(generateDependencies(clusterRoleBindings, clusterRoles, nodes, pods));
    dependencies.addAll(generateDependencies(roleBindings, roles, nodes, pods));
    resources.put(ResourceType.DEPENDENCY_REPORT, dependencies);
  }

  /**
   * Generates dependencies.
   * @param roleBindings list of either {@link ClusterRoleBinding}s or {@link RoleBinding}s
   * @param roles        list of either {@link ClusterRole}s or {@link Role}s
   * @param nodes        list of nodes
   * @param pods         list of pods
   * @return list of generated dependencies
   */
  @VisibleForTesting
  static List<Asset> generateDependencies(
      List<Asset> roleBindings,
      List<Asset> roles, List<Asset> nodes,
      List<Asset> pods) {
    if (roleBindings == null || roles == null || nodes == null || pods == null) {
      return Collections.emptyList();
    }

    List<Asset> dependencies = new ArrayList<>();

    HashSet<String> defaultServiceAccounts = KubernetesClusterDefaults
        .getKubernetesDefaults(ResourceType.SERVICE_ACCOUNT);
    for (Asset roleBinding : roleBindings) {
      KubernetesRoleBinding binding = (KubernetesRoleBinding) roleBinding;
      KubernetesRole role = (KubernetesRole) DetectorUtil
          .getFromCollection(roles, binding.getRoleRefName(), Asset::getAssetName);

      List<V1beta1Subject> subjects = binding.getSubjects();
      if (subjects == null) {
        continue;
      }

      for (V1beta1Subject subject : subjects) {
        if (subject.getKind().equals("ServiceAccount") || subject.getKind().equals("Group")) {
          for (Asset asset : pods) {
            Pod pod = (Pod) asset;

            String serviceAccount = subject.getNamespace() + "/" + subject.getName();
            if (!includeDefaults && defaultServiceAccounts.contains(serviceAccount)) {
              continue;
            }

            if (pod.getServiceAccount() != null && pod.getServiceAccount().equals(serviceAccount)) {
              Node node = (Node) DetectorUtil
                  .getFromCollection(nodes, pod.getNodeName(), n -> ((Node) n).getNodeName());

              if (node != null) {
                  Dependency dependency = new Dependency(binding, role, serviceAccount, node, pod);
                  dependencies.add(dependency);
              }
            }
          }
        }
      }
    }
    return dependencies;
  }

  /**
   * Fetches pod security policies from the api and stores them in the resource cache.
   * @throws ApiException in case of API communication error
   */
  private static void fetchPodSecurityPolicies() throws ApiException {
    PolicyV1beta1PodSecurityPolicyList pspList = policyApi.listPodSecurityPolicy(null, null, null,
        null, null, null,
        null, null, null);

    resources.put(ResourceType.POD_SECURITY_POLICY,
        pspList.getItems().stream().map(PodSecurityPolicy::new)
            .collect(Collectors.toList()));
  }

  /**
   * Fetches the resources of type @param assetTypeFilter.
   * <p>
   * If the resources were already fetched, they will be fetched from the cache. If not, resources
   * will be fetched from the API and cached for future use.
   * @param assetTypeFilter asset type of the assets to be fetched
   */
  private static List<Asset> getAssets(ResourceType assetTypeFilter) {
    if (assetTypeFilter == null) {
      return Collections.emptyList();
    }
    // Fetch from API.
    if (!resources.containsKey(assetTypeFilter)) {
      try {
        resourceFetchFunctions.get(assetTypeFilter).fetchAndCacheResource();
      } catch (ApiException e) {
        System.err.println("An exception occurred while communicating with the API.");
        System.exit(0);
      }
    }

    // Fetch cached.
    if (includeDefaults) {
      return resources.get(assetTypeFilter);
    }
    return retrieveAndFilterDefaults(assetTypeFilter);
  }

  /**
   * Retrieves resources of the given type from the cache, without default K8s resources.
   * @param assetTypeFilter asset filter
   * @return filtered list of resources
   */
  private static List<Asset> retrieveAndFilterDefaults(ResourceType assetTypeFilter) {
    HashSet<String> defaults = KubernetesClusterDefaults.getKubernetesDefaults(assetTypeFilter);
    return resources.get(assetTypeFilter).stream()
        .filter(asset -> !defaults.contains(asset.getAssetName()))
        .collect(Collectors.toList());
  }

  /**
   * Fetches the assets of the given types.
   * @param assetTypeFilters asset types of the assets to be fetched
   */
  public static List<Asset> getAssets(ResourceType[] assetTypeFilters) {
    List<Asset> assets = new ArrayList<>();
    for (ResourceType filter : assetTypeFilters) {
      assets.addAll(getAssets(filter));
    }
    return assets;
  }

  /**
   * An interface for fetching resources from K8s APIs.
   */
  interface ResourceFetchFunction {

    void fetchAndCacheResource() throws ApiException;

  }

}
