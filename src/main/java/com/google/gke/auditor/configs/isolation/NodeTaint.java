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
import io.kubernetes.client.openapi.models.V1Taint;
import io.kubernetes.client.openapi.models.V1Toleration;
import java.util.ArrayList;
import java.util.List;

/**
 * A detector searching for pods rejected by nodes because of missing pod tolerations for matching
 * node taints.
 */
public class NodeTaint extends NodeIsolationDetectorConfig {

  @Override
  public String getDetectorName() {
    return "NODE_TAINT";
  }

  /**
   * Checks if the pod was rejected from the node based on node taints.
   * <p>
   * Taints and tolerations work together to ensure that pods are not scheduled onto inappropriate
   * nodes. One or more taints are applied to a node; this marks that the node should not accept any
   * pods that do not tolerate the taints.
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

    List<V1Toleration> tolerations = nodePodBinding.getPod().getTolerations();
    List<V1Taint> taints = nodePodBinding.getNode().getTaints();
    if (tolerations == null || taints == null) {
      return false;
    }

    List<LabelSelector> missingLabelSelectors = new ArrayList<>();
    for (V1Taint taint : taints) {
      boolean hasMatchingToleration = false;
      for (V1Toleration toleration : tolerations) {
        if (areMatching(toleration, taint)) {
          hasMatchingToleration = true;
          break;
        }
      }

      if (!hasMatchingToleration) {
        missingLabelSelectors
            .add(new LabelSelector(taint.getKey(), taint.getValue(), "Effect", taint.getEffect()));
      }
    }

    nodePodBinding.addMissingLabelSelectors(missingLabelSelectors);
    return missingLabelSelectors.size() > 0;
  }

  /**
   * Checks if the pod toleration matches the node taint.
   * <p>
   * A toleration "matches" a taint if the keys are the same and the effects are the same, and: the
   * operator is Exists (in which case no value should be specified), or the operator is Equal and
   * the values are equal.
   * <p>
   * There are two special cases: an empty key with operator Exists matches all keys, values and
   * effects which means this will tolerate everything. An empty effect matches all effects with key
   * key.
   * @param toleration pod toleration
   * @param taint      node taint
   * @return true if the toleration and taint match, false otherwise
   */
  private boolean areMatching(V1Toleration toleration, V1Taint taint) {
    if (toleration.getKey() == null || toleration.getEffect() == null) {
      return false;
    }

    boolean tolerationMatchesTaint = toleration.getKey().equals(taint.getKey())
        && areMatchingOnEffect(toleration, taint)
        && ("Exists".equals(toleration.getOperator())
        || "Equal".equals(toleration.getOperator()) && toleration.getValue() != null
        && toleration.getValue().equals(taint.getValue()));

    return tolerationMatchesTaint || isTolerationKeyEmpty(toleration);
  }

  /**
   * Checks if the toleration key is empty.
   * @param toleration toleration to check
   * @return true if the key is empty, false otherwise
   */
  private boolean isTolerationKeyEmpty(V1Toleration toleration) {
    return toleration.getKey() != null && toleration.getKey().isEmpty();
  }

  /**
   * Returns true if the toleration and taint effects match. The effects either have to be the same,
   * or the toleration effect is empty and matches all effects.
   * @param toleration toleration
   * @param taint      taint
   * @return true if the toleration and taint match, false otherwise
   */
  private boolean areMatchingOnEffect(V1Toleration toleration, V1Taint taint) {
    return toleration.getEffect() != null
        && (toleration.getEffect().isEmpty() || toleration.getEffect().equals(taint.getEffect()));
  }


  @Override
  public String getExplanationText() {
    return "Taints allow a node to repel a set of pods. Tolerations are applied to pods, and allow "
        + "(but do not require) the pods to schedule onto nodes with matching taints. Taints and "
        + "tolerations work together to ensure that pods are not scheduled onto inappropriate nodes. "
        + "One or more taints are applied to a node; this marks that the node should not accept any "
        + "pods that do not tolerate the taints.";
  }

  @Override
  public List<String> getUsefulURLs() {
    return List
        .of("https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/");
  }

}
