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

/**
 * Resource types used by the auditor.
 */
public enum ResourceType {
  /**
   * Provides an identity for processes that run in a Pod.
   */
  SERVICE_ACCOUNT,
  /**
   * May be a virtual of physical machine, depending on the cluster. Contains services necessary to
   * run pods.
   */
  NODE,
  /**
   * Smallest deployable unit of computing in K8s. A group of one or more containers, with shared
   * storage/network resources, and a specification for how to run the containers.
   */
  POD,
  /**
   * Contains rules that represent a set of permissions withing a particular namespace.
   */
  ROLE,
  /**
   * Grants the permissions defined in a role to a user or set of users within a specific
   * namespace.
   */
  ROLE_BINDING,
  /**
   * Contains rules that represent a set of permissions, non-namespaced. Defines permissions
   * cluster-wide.
   */
  CLUSTER_ROLE,
  /**
   * Grants the permissions defined in a role to a user or set of users cluster-wide.
   */
  CLUSTER_ROLE_BINDING,
  /**
   * A cluster-level resource that controls security sensitive aspects of the pod specification.
   */
  POD_SECURITY_POLICY,

  NODE_POD_BINDING,
  DEPENDENCY_REPORT
}
