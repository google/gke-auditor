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

import com.google.gke.auditor.models.Asset;
import com.google.gke.auditor.models.NodePodBinding;
import com.google.gke.auditor.models.NodePodBinding.LabelSelector;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

/**
 * A detector searching for pods rejected by nodes because of missing node selectors.
 */
public class NodeSelector extends NodeIsolationDetectorConfig {

  @Override
  public String getDetectorName() {
    return "NODE_SELECTOR";
  }

  /**
   * A detector auditing the nodeSelectors required for a pod to be scheduled onto a node. Checks if
   * the pod was rejected from the node based on the nodeSelectors.
   * <p>
   * For the pod to be eligible to run on a node, the node must have each of the indicated key-value
   * pairs as labels (it can have additional labels as well). The most common usage is one key-value
   * pair.
   * @param asset asset to audit
   * @return true if asset is vulnerable, false otherwise
   */
  @Override
  public Boolean isVulnerable(Asset asset) {
    NodePodBinding nodePodBinding = getNodePodBinding(asset);
    if (nodePodBinding == null
        || nodePodBinding.getNode() == null
        || nodePodBinding.getPod() == null) {
      return false;
    }

    Map<String, String> labels = nodePodBinding.getNode().getLabels();
    Map<String, String> nodeSelectors = nodePodBinding.getPod().getNodeSelectors();

    List<LabelSelector> missingLabelSelectors = new ArrayList<>();
    for (Entry<String, String> entry : nodeSelectors.entrySet()) {
      if (!entry.getValue().equals(labels.getOrDefault(entry.getKey(), null))) {
        missingLabelSelectors.add(new LabelSelector(entry.getKey(), entry.getValue()));
      }
    }

    nodePodBinding.addMissingLabelSelectors(missingLabelSelectors);
    return missingLabelSelectors.size() > 0;
  }

  @Override
  public String getExplanationText() {
    return "nodeSelector is the simplest recommended form of node selection constraint. "
        + "nodeSelector specifies a map of key-value pairs. For the pod to be eligible to run on "
        + "a node, the node must have each of the indicated key-value pairs as labels (it can have "
        + "additional labels as well). The most common usage is one key-value pair.";
  }

  @Override
  public List<String> getUsefulURLs() {
    return List
        .of("https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector");
  }

}
