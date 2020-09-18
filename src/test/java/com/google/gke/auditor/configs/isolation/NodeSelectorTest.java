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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.gke.auditor.models.Node;
import com.google.gke.auditor.models.NodePodBinding;
import com.google.gke.auditor.models.Pod;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A test for {@link NodeSelector}.
 */
public class NodeSelectorTest {

  private NodeSelector nodeSelector;

  @BeforeEach
  public void init() {
    nodeSelector = new NodeSelector();
  }

  @Test
  public void getExplanationTextTest() {
    assertThat(nodeSelector.getExplanationText()).isNotEmpty();
  }

  @Test
  public void getRecommendationTextTest() {
    assertThat(nodeSelector.getRecommendationText()).isNotEmpty();
  }

  @Test
  public void getDetectorNameTest() {
    assertThat(nodeSelector.getDetectorName()).isNotEmpty();
    assertThat(nodeSelector.getDetectorName()).isEqualTo("NODE_SELECTOR");
  }

  @Test
  public void getUsefulURLsTest() {
    List<String> usefulUrls = List
        .of("https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector");
    assertThat(nodeSelector.getUsefulURLs()).isNotNull();
    assertThat(nodeSelector.getUsefulURLs()).containsAll(usefulUrls);
  }

  @Test
  public void isVulnerableNullTest() {
    NodePodBinding nodePodBinding = mock(NodePodBinding.class);
    when(nodePodBinding.getNode()).thenReturn(null);
    when(nodePodBinding.getPod()).thenReturn(null);

    assertThat(nodeSelector.isVulnerable(nodePodBinding)).isFalse();
  }

  @Test
  public void isVulnerableEmptyNodeLabelsAndPodSelectorsTest() {
    Node node = mock(Node.class);
    when(node.getLabels()).thenReturn(Collections.emptyMap());

    Pod pod = mock(Pod.class);
    when(pod.getNodeSelectors()).thenReturn(Collections.emptyMap());

    NodePodBinding nodePodBinding = mock(NodePodBinding.class);
    when(nodePodBinding.getNode()).thenReturn(node);
    when(nodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeSelector.isVulnerable(nodePodBinding)).isFalse();
  }

  @Test
  public void isVulnerableEmptyPodSelectorsTest() {
    Node node = mock(Node.class);
    when(node.getLabels()).thenReturn(Map.of("test-key-first", "test-value-first",
        "test-key-second", "test-value-second"));

    Pod pod = mock(Pod.class);
    when(pod.getNodeSelectors()).thenReturn(Collections.emptyMap());

    NodePodBinding nodePodBinding = mock(NodePodBinding.class);
    when(nodePodBinding.getNode()).thenReturn(node);
    when(nodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeSelector.isVulnerable(nodePodBinding)).isFalse();
  }

  @Test
  public void isVulnerableEmptyNodeLabelsTest() {
    Node node = mock(Node.class);
    when(node.getLabels()).thenReturn(Collections.emptyMap());

    Pod pod = mock(Pod.class);
    when(pod.getNodeSelectors()).thenReturn(Map.of("test-key-first", "test-value-first",
        "test-key-second", "test-value-second"));

    NodePodBinding nodePodBinding = mock(NodePodBinding.class);
    when(nodePodBinding.getNode()).thenReturn(node);
    when(nodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeSelector.isVulnerable(nodePodBinding)).isTrue();
  }

  @Test
  public void isVulnerableAllNodeSelectorsMatchTest() {
    Node node = mock(Node.class);
    when(node.getLabels()).thenReturn(Map.of("test-key-first", "test-value-first",
        "test-key-second", "test-value-second",
        "test-key-third", "test-value-third"));

    Pod pod = mock(Pod.class);
    when(pod.getNodeSelectors()).thenReturn(Map.of("test-key-first", "test-value-first",
        "test-key-second", "test-value-second"));

    NodePodBinding nodePodBinding = mock(NodePodBinding.class);
    when(nodePodBinding.getNode()).thenReturn(node);
    when(nodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeSelector.isVulnerable(nodePodBinding)).isFalse();
  }

  @Test
  public void isVulnerableNodeSelectorsLabelMissingTest() {
    Node node = mock(Node.class);
    when(node.getLabels()).thenReturn(Map.of("test-key-first", "test-value-first",
        "test-key-second", "test-value-second",
        "test-key-third", "test-value-third"));

    Pod pod = mock(Pod.class);
    when(pod.getNodeSelectors()).thenReturn(Map.of("test-key-first", "test-value-first",
        "test-key-second", "test-value-second",
        "missing-key", "missing-label"));

    NodePodBinding nodePodBinding = mock(NodePodBinding.class);
    when(nodePodBinding.getNode()).thenReturn(node);
    when(nodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeSelector.isVulnerable(nodePodBinding)).isTrue();
  }

  @Test
  public void isVulnerableNodeSelectorsLabelValueNotMatchingTest() {
    Node node = mock(Node.class);
    when(node.getLabels()).thenReturn(Map.of("test-key-first", "test-value-first",
        "test-key-second", "test-value-second",
        "matching-key", "matching-value"));

    Pod pod = mock(Pod.class);
    when(pod.getNodeSelectors()).thenReturn(Map.of("test-key-first", "test-value-first",
        "test-key-second", "test-value-second",
        "matching-key", "non-matching-value"));

    NodePodBinding nodePodBinding = mock(NodePodBinding.class);
    when(nodePodBinding.getNode()).thenReturn(node);
    when(nodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeSelector.isVulnerable(nodePodBinding)).isTrue();
  }


}