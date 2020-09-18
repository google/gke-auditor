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

package com.google.gke.auditor.configs.util;

import java.util.Arrays;
import java.util.HashSet;

/**
 * Utility class for collections of escalating resources.
 */
public class EscalatingResources {

  /**
   * Collection of escalating resources.
   */
  public static final HashSet<String> ESCALATING_RESOURCES = new HashSet<>(
      Arrays.asList("secrets", "*", "*/*"));
  /**
   * Collection of escalating verbs.
   */
  public static final HashSet<String> ESCALATING_VERBS = new HashSet<>(Arrays
      .asList("create", "edit", "delete", "proxy",
          "patch", "update", "*"));
  /**
   * Collection of escalation subresources.
   */
  public static final HashSet<String> ESCALATING_SUBRESOURCES =
      new HashSet<>(Arrays.asList("exec", "attach",
          "portforward", "proxy"));
  /**
   * Collection of resources that could be escalated from on write.
   */
  public static final HashSet<String> ESCALATING_RESOURCES_ON_WRITE = new HashSet<>(Arrays.asList(
      "apps/daemonsets", "apps/daemonsets/*",
      "apps/deployments", "apps/deployments/*",
      "apps/replicasets", "apps/replicasets/*",
      "apps/statefulsets", "apps/statefulsets/*",
      "authentication.k8s.io/tokenrequests", "authentication.k8s.io/tokenrequests/*",
      "batch/jobs", "batch/jobs/*",
      "configmaps", "configmaps/*",
      "extensions/daemonsets", "extensions/daemonsets/*",
      "extensions/deployments", "extensions/deployments/*",
      "extensions/replicasets", "extensions/replicasets/*",
      "nodes", "nodes/*",
      "pods", "pods/*",
      "rbac.authorization.k8s.io/clusterrolebindings",
      "rbac.authorization.k8s.io/clusterrolebindings/*",
      "rbac.authorization.k8s.io/clusterroles", "rbac.authorization.k8s.io/clusterroles/*",
      "rbac.authorization.k8s.io/rolebindings", "rbac.authorization.k8s.io/rolebindings/*",
      "rbac.authorization.k8s.io/roles", "rbac.authorization.k8s.io/roles/*",
      "replicationcontrollers", "replicationcontrollers/*",
      "serviceaccounts", "serviceaccounts/*"
  ));

}
