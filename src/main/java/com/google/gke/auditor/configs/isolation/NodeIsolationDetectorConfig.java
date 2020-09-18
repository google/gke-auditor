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

package com.google.gke.auditor.configs.isolation;

import com.google.gke.auditor.configs.KubernetesDetectorConfig;
import com.google.gke.auditor.configs.util.MisconfigurationLevel;
import com.google.gke.auditor.configs.util.Severity;
import com.google.gke.auditor.models.Asset;
import com.google.gke.auditor.models.NodePodBinding;
import com.google.gke.auditor.system.ResourceType;
import java.util.List;

/**
 * An abstract implementation of {@link KubernetesDetectorConfig}.
 * <p>
 * Provides default implementation methods shared by Node Isolation detectors. All Node Isolation
 * detectors should extend this class.
 */
public abstract class NodeIsolationDetectorConfig extends KubernetesDetectorConfig {

  @Override
  public ResourceType getAssetFilter() {
    return ResourceType.NODE_POD_BINDING;
  }

  @Override
  public String getRecommendationText() {
    return "Review which pods were rejected by nodes and ensure this complies with the desired behaviour.";
  }

  @Override
  public MisconfigurationLevel getMisconfigurationLevel() {
    return MisconfigurationLevel.WARNING;
  }

  @Override
  public Severity getSeverity() {
    return Severity.LOW;
  }

  /**
   * Returns the asset as a {@link NodePodBinding}, or null if such conversion is not possible.
   * @param asset asset to convert
   * @return asset as a {@link NodePodBinding}
   */
  NodePodBinding getNodePodBinding(Asset asset) {
    if (asset instanceof NodePodBinding) {
      return ((NodePodBinding) asset);
    }
    return null;
  }

  @Override
  public List<String> getUsefulURLs() {
    return List.of("https://kubernetes.io/docs/concepts/scheduling-eviction/");
  }

}
