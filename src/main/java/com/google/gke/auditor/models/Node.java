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
import com.google.gke.auditor.system.Logger.Color;
import com.google.gke.auditor.system.ResourceType;
import io.kubernetes.client.openapi.models.V1Node;
import io.kubernetes.client.openapi.models.V1NodeSpec;
import io.kubernetes.client.openapi.models.V1ObjectMeta;
import io.kubernetes.client.openapi.models.V1Taint;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * A wrapper class around {@link V1Node}.
 */
public class Node extends Asset {

  /**
   * API Node reference.
   */
  private final V1Node node;

  /**
   * Initialize the Node.
   * @param node api node reference
   */
  public Node(V1Node node) {
    this.node = node;
  }

  @Override
  public String getAssetName() {
    if (node.getMetadata() != null) {
      return node.getMetadata().getName();
    }
    return null;
  }

  @Override
  public Logger.Builder getReport() {
    return Logger.builder()
        .addMessage("Node", getAssetName(), Color.RED);
  }

  @Override
  public String toString() {
    return String.format("Node: %s", getNodeName());
  }

  @Override
  public ResourceType getResourceType() {
    return ResourceType.NODE;
  }

  /**
   * Returns the node name.
   * @return node name
   */
  public String getNodeName() {
    if (node.getMetadata() != null) {
      return node.getMetadata().getName();
    }
    return null;
  }

  /**
   * Returns a map of node labels, or an empty map if there is none.
   * @return map of node labels
   */
  public Map<String, String> getLabels() {
    return Optional.ofNullable(node.getMetadata())
        .map(V1ObjectMeta::getLabels)
        .orElse(Collections.emptyMap());
  }

  /**
   * Returns a list of node {@link V1Taint}s, or an empty list if there is none.
   * @return map of node taints
   */
  public List<V1Taint> getTaints() {
    return Optional.ofNullable(node.getSpec())
        .map(V1NodeSpec::getTaints)
        .orElse(Collections.emptyList());
  }

}
