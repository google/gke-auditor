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

package com.google.gke.auditor.models;

import com.google.gke.auditor.system.Logger;
import com.google.gke.auditor.system.ResourceType;
import java.util.ArrayList;
import java.util.List;

/**
 * A wrapper class for a {@link Node} and {@link Pod}.
 * <p>
 * Used in node isolation detectors for testing the possibility of scheduling the pod onto the
 * node.
 */
public class NodePodBinding extends Asset {

  /**
   * K8s node.
   */
  private final Node node;
  /**
   * K8s pod.
   */
  private final Pod pod;

  /**
   * A list of missing {@link LabelSelector}s preventing the pod to be successfully scheduled on the
   * node.
   */
  private List<LabelSelector> missingLabelSelectors = new ArrayList<>();

  /**
   * Initialize NodePodBinding.
   * @param node node
   * @param pod  pod
   */
  public NodePodBinding(Node node, Pod pod) {
    this.node = node;
    this.pod = pod;
  }

  /**
   * Add {@link LabelSelector}s preventing the pod to be scheduled onto the node.
   */
  public void addMissingLabelSelectors(List<LabelSelector> labelSelectors) {
    this.missingLabelSelectors.addAll(labelSelectors);
  }

  @Override
  public ResourceType getResourceType() {
    return ResourceType.NODE_POD_BINDING;
  }

  @Override
  public Logger.Builder getReport() {
    Logger.Builder nodeBuilder = node.getReport();
    Logger.Builder podBuilder = pod.getReport();
    if (!missingLabelSelectors.isEmpty()) {
      podBuilder
          .addMessage("rejected because of missing label selectors:", Logger.Color.RED);

      Logger.Builder labelSelectorBuilder = Logger.builder();
      for (LabelSelector selector : missingLabelSelectors) {
        labelSelectorBuilder.addMessages(selector.getReport().getMessages()).addLineBreak();
      }

      missingLabelSelectors.clear();
      podBuilder.addSubMessages(labelSelectorBuilder);
    }

    nodeBuilder.addSubMessages(podBuilder);
    return nodeBuilder;
  }

  @Override
  public String toString() {
    return String.format("%s\n\t\t%s", node.toString(), pod.toString());
  }

  @Override
  public String getAssetName() {
    return String.format("Node: %s, Pod: %s", node.getAssetName(), pod.getAssetName());
  }

  /**
   * Retrieves the node associated with this binding.
   * @return node
   */
  public Node getNode() {
    return node;
  }

  /**
   * Retrieves the pod associated with this binding.
   * @return pod
   */
  public Pod getPod() {
    return pod;
  }

  /**
   * A wrapper class for a label selector.
   * <p>
   * Represents either a node selector (key-value pair), a {@link io.kubernetes.client.openapi.models.V1NodeSelectorRequirement}
   * (key-value pair with additional "Operator" field), or {@link io.kubernetes.client.openapi.models.V1Taint}
   * (key-value pair with additional "Effect" field).
   */
  public static class LabelSelector {

    /**
     * Key of the selector.
     */
    private final String key;
    /**
     * Value of the selector.
     */
    private final String value;
    /**
     * Null where not used, else either "Operator" or "Effect".
     */
    private String optionalKey;
    /**
     * Null where not used, else the value of the additional field.
     */
    private String optionalValue;

    /**
     * Initialize a label selector without an additional field.
     * @param key   selector key
     * @param value selector value
     */
    public LabelSelector(String key, String value) {
      this.key = key;
      this.value = value;
    }

    /**
     * Initialize a label selector with an additional field.
     * @param key           selector key
     * @param value         selector value
     * @param optionalKey   additional selector key (either "Operator" or "Effect")
     * @param optionalValue additional selector value
     */
    public LabelSelector(String key, String value, String optionalKey, String optionalValue) {
      this.key = key;
      this.value = value;
      this.optionalKey = optionalKey;
      this.optionalValue = optionalValue;
    }

    /**
     * Retrieves the {@link Logger.Builder} representation of the {@link LabelSelector}.
     * @return representation of the label selector
     */
    public Logger.Builder getReport() {
      Logger.Builder builder = Logger.builder()
          .addMessage("Key", key, Logger.Color.RED)
          .addMessage("Value", value, Logger.Color.RED);

      if (optionalKey != null && optionalValue != null) {
        builder.addMessage(optionalKey, optionalValue, Logger.Color.RED);
      }
      return builder;
    }

  }

}
