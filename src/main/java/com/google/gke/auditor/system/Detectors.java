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

import com.google.gke.auditor.configs.DetectorConfig;
import com.google.gke.auditor.configs.isolation.NodeAffinity;
import com.google.gke.auditor.configs.isolation.NodeSelector;
import com.google.gke.auditor.configs.isolation.NodeTaint;
import com.google.gke.auditor.configs.psp.AddedCapabilities;
import com.google.gke.auditor.configs.psp.AllowPrivilegeEscalation;
import com.google.gke.auditor.configs.psp.CapabilitiesAssigned;
import com.google.gke.auditor.configs.psp.NetRawCapabilities;
import com.google.gke.auditor.configs.psp.PrivilegedContainers;
import com.google.gke.auditor.configs.psp.RootContainersAdmission;
import com.google.gke.auditor.configs.psp.SharingHostIPC;
import com.google.gke.auditor.configs.psp.SharingHostNetworkNamespace;
import com.google.gke.auditor.configs.psp.SharingHostPIDNamespace;
import com.google.gke.auditor.configs.rbac.AccessToSecrets;
import com.google.gke.auditor.configs.rbac.AutomountServiceAccountTokenEnabled;
import com.google.gke.auditor.configs.rbac.ClusterAdminRoleUsed;
import com.google.gke.auditor.configs.rbac.CreatePodsAllowed;
import com.google.gke.auditor.configs.rbac.EscalatingResourcesDependencyReport;
import com.google.gke.auditor.configs.rbac.WildcardUsed;
import java.util.Arrays;
import java.util.List;

/**
 * Utility class for storing grouped collections of implemented detectors.
 */
public class Detectors {

  /**
   * All RBAC detectors supported by the auditor.
   */
  public static final List<DetectorConfig> RBAC_DETECTORS = Arrays.asList(
      new ClusterAdminRoleUsed(),
      new AccessToSecrets(),
      new WildcardUsed(),
      new CreatePodsAllowed(),
      new AutomountServiceAccountTokenEnabled(),
      new EscalatingResourcesDependencyReport()
  );

  /**
   * All node isolation detectors supported by the auditor.
   */
  public static final List<DetectorConfig> ISOLATION_DETECTORS = Arrays.asList(
      new NodeSelector(),
      new NodeAffinity(),
      new NodeTaint()
  );

  /**
   * All PSP detectors supported by the auditor.
   */
  public static final List<DetectorConfig> PSP_DETECTORS = Arrays.asList(
      new PrivilegedContainers(),
      new SharingHostPIDNamespace(),
      new SharingHostIPC(),
      new SharingHostNetworkNamespace(),
      new AllowPrivilegeEscalation(),
      new RootContainersAdmission(),
      new NetRawCapabilities(),
      new AddedCapabilities(),
      new CapabilitiesAssigned()
  );

}
