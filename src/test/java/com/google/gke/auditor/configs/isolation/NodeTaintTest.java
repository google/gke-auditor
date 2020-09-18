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
import io.kubernetes.client.openapi.models.V1Taint;
import io.kubernetes.client.openapi.models.V1Toleration;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A test for {@link NodeTaint}.
 */
public class NodeTaintTest {

  private NodeTaint nodeTaint;

  @BeforeEach
  public void init() {
    nodeTaint = new NodeTaint();
  }

  @Test
  public void getExplanationTextTest() {
    assertThat(nodeTaint.getExplanationText()).isNotEmpty();
  }

  @Test
  public void getRecommendationTextTest() {
    assertThat(nodeTaint.getRecommendationText()).isNotEmpty();
  }

  @Test
  public void getDetectorNameTest() {
    assertThat(nodeTaint.getDetectorName()).isNotEmpty();
    assertThat(nodeTaint.getDetectorName()).isEqualTo("NODE_TAINT");
  }

  @Test
  public void getUsefulURLsTest() {
    List<String> usefulUrls = List
        .of("https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/");
    assertThat(nodeTaint.getUsefulURLs()).isNotNull();
    assertThat(nodeTaint.getUsefulURLs()).containsAll(usefulUrls);
  }

  @Test
  public void isVulnerableNullTest() {
    NodePodBinding nodePodBinding = mock(NodePodBinding.class);
    when(nodePodBinding.getNode()).thenReturn(null);
    when(nodePodBinding.getPod()).thenReturn(null);

    assertThat(nodeTaint.isVulnerable(nodePodBinding)).isFalse();
  }

  @Test
  public void isVulnerableTaintsTolerationsNullTest() {
    Node node = mock(Node.class);
    when(node.getTaints()).thenReturn(null);

    Pod pod = mock(Pod.class);
    when(pod.getTolerations()).thenReturn(null);

    NodePodBinding nodePodBinding = mock(NodePodBinding.class);
    when(nodePodBinding.getNode()).thenReturn(node);
    when(nodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeTaint.isVulnerable(nodePodBinding)).isFalse();
  }

  @Test
  public void isVulnerableEmptyTaintsTest() {
    Node node = mock(Node.class);
    when(node.getTaints()).thenReturn(Collections.emptyList());

    V1Toleration toleration = mock(V1Toleration.class);
    when(toleration.getKey()).thenReturn("test-key");
    when(toleration.getValue()).thenReturn("test-value");

    Pod pod = mock(Pod.class);
    when(pod.getTolerations()).thenReturn(List.of(toleration));

    NodePodBinding nodePodBinding = mock(NodePodBinding.class);
    when(nodePodBinding.getNode()).thenReturn(node);
    when(nodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeTaint.isVulnerable(nodePodBinding)).isFalse();
  }


  @Test
  public void isVulnerableEmptyTolerationsTest() {
    V1Taint taint = mock(V1Taint.class);
    when(taint.getKey()).thenReturn("test-key");
    when(taint.getValue()).thenReturn("test-value");

    Node node = mock(Node.class);
    when(node.getTaints()).thenReturn(List.of(taint));

    Pod pod = mock(Pod.class);
    when(pod.getTolerations()).thenReturn(Collections.emptyList());

    NodePodBinding nodePodBinding = mock(NodePodBinding.class);
    when(nodePodBinding.getNode()).thenReturn(node);
    when(nodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeTaint.isVulnerable(nodePodBinding)).isTrue();
  }

  @Test
  public void isVulnerableTaintHasNoMatchingTolerationTest() {
    V1Taint firstTaint = mock(V1Taint.class);
    when(firstTaint.getKey()).thenReturn("test-key");
    when(firstTaint.getValue()).thenReturn("test-value");
    when(firstTaint.getEffect()).thenReturn("NoSchedule");

    // No matching toleration.
    V1Taint secondTaint = mock(V1Taint.class);
    when(secondTaint.getKey()).thenReturn("other-test-key");
    when(secondTaint.getValue()).thenReturn("other-test-value");
    when(secondTaint.getEffect()).thenReturn("NoSchedule");

    Node node = mock(Node.class);
    when(node.getTaints()).thenReturn(List.of(firstTaint, secondTaint));

    V1Toleration toleration = mock(V1Toleration.class);
    when(toleration.getKey()).thenReturn("test-key");
    when(toleration.getValue()).thenReturn("test-value");
    when(toleration.getEffect()).thenReturn("NoSchedule");
    when(toleration.getOperator()).thenReturn("Equal");

    Pod pod = mock(Pod.class);
    when(pod.getTolerations()).thenReturn(List.of(toleration));

    NodePodBinding nodePodBinding = mock(NodePodBinding.class);
    when(nodePodBinding.getNode()).thenReturn(node);
    when(nodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeTaint.isVulnerable(nodePodBinding)).isTrue();
  }

  @Test
  public void isVulnerableTaintsWithMatchingTolerationsTest() {
    V1Taint firstTaint = mock(V1Taint.class);
    when(firstTaint.getKey()).thenReturn("test-key");
    when(firstTaint.getValue()).thenReturn("test-value");
    when(firstTaint.getEffect()).thenReturn("NoSchedule");

    V1Taint secondTaint = mock(V1Taint.class);
    when(secondTaint.getKey()).thenReturn("other-test-key");
    when(secondTaint.getEffect()).thenReturn("NoSchedule");

    Node node = mock(Node.class);
    when(node.getTaints()).thenReturn(List.of(firstTaint, secondTaint));

    V1Toleration firstToleration = mock(V1Toleration.class);
    when(firstToleration.getKey()).thenReturn("test-key");
    when(firstToleration.getValue()).thenReturn("test-value");
    when(firstToleration.getEffect()).thenReturn("NoSchedule");
    when(firstToleration.getOperator()).thenReturn("Equal");

    V1Toleration secondToleration = mock(V1Toleration.class);
    when(secondToleration.getKey()).thenReturn("other-test-key");
    when(secondToleration.getEffect()).thenReturn("NoSchedule");
    when(secondToleration.getOperator()).thenReturn("Exists");

    Pod pod = mock(Pod.class);
    when(pod.getTolerations()).thenReturn(List.of(firstToleration, secondToleration));

    NodePodBinding nodePodBinding = mock(NodePodBinding.class);
    when(nodePodBinding.getNode()).thenReturn(node);
    when(nodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeTaint.isVulnerable(nodePodBinding)).isFalse();
  }


  @Test
  public void isVulnerableTolerationWithEmptyKey() {
    V1Taint firstTaint = mock(V1Taint.class);
    when(firstTaint.getKey()).thenReturn("test-key");
    when(firstTaint.getValue()).thenReturn("test-value");
    when(firstTaint.getEffect()).thenReturn("NoSchedule");

    V1Taint secondTaint = mock(V1Taint.class);
    when(secondTaint.getKey()).thenReturn("other-test-key");
    when(secondTaint.getEffect()).thenReturn("NoSchedule");

    Node node = mock(Node.class);
    when(node.getTaints()).thenReturn(List.of(firstTaint, secondTaint));

    V1Toleration firstToleration = mock(V1Toleration.class);
    when(firstToleration.getKey()).thenReturn("");
    when(firstToleration.getValue()).thenReturn("test-value");
    when(firstToleration.getEffect()).thenReturn("NoSchedule");
    when(firstToleration.getOperator()).thenReturn("Exists");

    Pod pod = mock(Pod.class);
    when(pod.getTolerations()).thenReturn(List.of(firstToleration));

    NodePodBinding nodePodBinding = mock(NodePodBinding.class);
    when(nodePodBinding.getNode()).thenReturn(node);
    when(nodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeTaint.isVulnerable(nodePodBinding)).isFalse();
  }

  @Test
  public void isVulnerableTolerationWithEmptyEffect() {
    V1Taint firstTaint = mock(V1Taint.class);
    when(firstTaint.getKey()).thenReturn("test-key");
    when(firstTaint.getValue()).thenReturn("test-value");
    when(firstTaint.getEffect()).thenReturn("NoSchedule");

    Node node = mock(Node.class);
    when(node.getTaints()).thenReturn(List.of(firstTaint));

    V1Toleration firstToleration = mock(V1Toleration.class);
    when(firstToleration.getKey()).thenReturn("test-key");
    when(firstToleration.getValue()).thenReturn("test-value");
    when(firstToleration.getEffect()).thenReturn("");
    when(firstToleration.getOperator()).thenReturn("Exists");

    Pod pod = mock(Pod.class);
    when(pod.getTolerations()).thenReturn(List.of(firstToleration));

    NodePodBinding nodePodBinding = mock(NodePodBinding.class);
    when(nodePodBinding.getNode()).thenReturn(node);
    when(nodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeTaint.isVulnerable(nodePodBinding)).isFalse();
  }

}