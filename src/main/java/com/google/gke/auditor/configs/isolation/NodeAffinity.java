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
import io.kubernetes.client.openapi.models.V1NodeSelectorRequirement;
import io.kubernetes.client.openapi.models.V1NodeSelectorTerm;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang.StringUtils;

/**
 * A detector searching for pods rejected by nodes because of missing node affinity selectors.
 */
public class NodeAffinity extends NodeIsolationDetectorConfig {

  @Override
  public String getDetectorName() {
    return "NODE_AFFINITY";
  }

  /**
   * A detector auditing the requiredDuringSchedulingIgnoredDuringExecution node affinity that has
   * to be met for a pod to be scheduled onto a node. Checks if the pod was rejected from the node
   * based on node affinity selectors.
   * <p>
   * If you specify multiple nodeSelectorTerms associated with nodeAffinity types, then the pod can
   * be scheduled onto a node if one of the nodeSelectorTerms can be satisfied.
   * <p>
   * If you specify multiple matchExpressions associated with nodeSelectorTerms, then the pod can be
   * scheduled onto a node only if all matchExpressions is satisfied.
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
    List<V1NodeSelectorTerm> nodeSelectorTerms = nodePodBinding.getPod()
        .getNodeAffinitySelectorTerms();

    List<LabelSelector> missingLabelSelectors = new ArrayList<>();
    // Any nodeSelectorTerm must be satisfied.
    for (V1NodeSelectorTerm term : nodeSelectorTerms) {
      if (term.getMatchExpressions() == null) {
        continue;
      }

      boolean nodeSelectorTermMatches = true;
      // All matchExpressions must be satisfied.
      for (V1NodeSelectorRequirement matchExpression : term.getMatchExpressions()) {
        String value = labels.getOrDefault(matchExpression.getKey(), null);
        if (!matches(value, matchExpression.getOperator(), matchExpression.getValues())) {
          missingLabelSelectors.add(new LabelSelector(matchExpression.getKey(),
              matchExpression.getValues() == null ? "[]" : matchExpression.getValues().toString(),
              "Operator",
              matchExpression.getOperator()));
          nodeSelectorTermMatches = false;
        }
      }

      if (nodeSelectorTermMatches) {
        // Found a matching nodeSelectorTerm.
        return false;
      }
    }

    nodePodBinding.addMissingLabelSelectors(missingLabelSelectors);
    return missingLabelSelectors.size() > 0;
  }

  /**
   * Checks if the given value matches the given selector operator and values.
   * @param value            value to check
   * @param selectorOperator represents the relationship to a set of values
   * @param selectorValues   array of string values
   * @return true if the value matches, false otherwise
   */
  private boolean matches(String value, String selectorOperator, List<String> selectorValues) {
    if (selectorValues == null) {
      return false;
    }

    switch (selectorOperator) {
      case "In": {
        return value != null && selectorValues.contains(value);
      }
      case "NotIn": {
        return value != null && !selectorValues.contains(value);
      }
      case "Exists": {
        return value != null;
      }
      case "DoesNotExist": {
        return value == null;
      }
      case "Gt": {
        return StringUtils.isNumeric(value)
            && selectorValues.stream().allMatch(selector -> StringUtils.isNumeric(selector)
            && Integer.parseInt(value) > Integer.parseInt(selector));
      }
      case "Lt": {
        return StringUtils.isNumeric(value)
            && selectorValues.stream().allMatch(selector -> StringUtils.isNumeric(selector)
            && Integer.parseInt(value) < Integer.parseInt(selector));
      }
      default: {
        return false;
      }
    }
  }

  @Override
  public String getExplanationText() {
    return "Node affinity allows you to constrain which nodes your pod is eligible to be scheduled "
        + "on, based on labels on the node. It is conceptually similar to nodeSelector, but greatly "
        + "expands types of constraints you can express.";
  }

  @Override
  public List<String> getUsefulURLs() {
    return List
        .of("https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#affinity-and-anti-affinity");
  }

}