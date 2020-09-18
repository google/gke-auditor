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
import io.kubernetes.client.openapi.models.V1NodeSelectorRequirement;
import io.kubernetes.client.openapi.models.V1NodeSelectorTerm;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Test for {@link NodeAffinity}.
 */
public class NodeAffinityTest {

  private NodeAffinity nodeAffinity;

  @BeforeEach
  public void init() {
    nodeAffinity = new NodeAffinity();
  }

  @Test
  public void getExplanationTextTest() {
    assertThat(nodeAffinity.getExplanationText()).isNotEmpty();
  }

  @Test
  public void getRecommendationTextTest() {
    assertThat(nodeAffinity.getRecommendationText()).isNotEmpty();
  }

  @Test
  public void getDetectorNameTest() {
    assertThat(nodeAffinity.getDetectorName()).isNotEmpty();
    assertThat(nodeAffinity.getDetectorName()).isEqualTo("NODE_AFFINITY");
  }

  @Test
  public void getUsefulURLsTest() {
    NodeAffinity nodeAffinity = new NodeAffinity();
    List<String> usefulUrls = List
        .of("https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/" +
            "#affinity-and-anti-affinity");
    assertThat(nodeAffinity.getUsefulURLs()).isNotNull();
    assertThat(nodeAffinity.getUsefulURLs()).containsAll(usefulUrls);
  }

  @Test
  public void isVulnerableNullTest() {
    NodePodBinding nodePodBinding = mock(NodePodBinding.class);
    when(nodePodBinding.getNode()).thenReturn(null);
    when(nodePodBinding.getPod()).thenReturn(null);

    assertThat(nodeAffinity.isVulnerable(nodePodBinding)).isFalse();
  }


  @Test
  public void isVulnerableEmptyNodeLabelsAndPodSelectorsTest() {
    Node node = mock(Node.class);
    when(node.getLabels()).thenReturn(Collections.emptyMap());

    Pod pod = mock(Pod.class);
    when(pod.getNodeAffinitySelectorTerms()).thenReturn(Collections.emptyList());

    NodePodBinding nodePodBinding = mock(NodePodBinding.class);
    when(nodePodBinding.getNode()).thenReturn(node);
    when(nodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeAffinity.isVulnerable(nodePodBinding)).isFalse();
  }

  @Test
  public void isVulnerableEmptyPodSelectorsTest() {
    Node node = mock(Node.class);
    when(node.getLabels()).thenReturn(Map.of("test-key-first", "test-value-first",
        "test-key-second", "test-value-second"));

    Pod pod = mock(Pod.class);
    when(pod.getNodeAffinitySelectorTerms()).thenReturn(Collections.emptyList());

    NodePodBinding nodePodBinding = mock(NodePodBinding.class);
    when(nodePodBinding.getNode()).thenReturn(node);
    when(nodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeAffinity.isVulnerable(nodePodBinding)).isFalse();
  }

  @Test
  public void isVulnerableEmptyNodeLabelsTest() {
    Node node = mock(Node.class);
    when(node.getLabels()).thenReturn(Collections.emptyMap());

    V1NodeSelectorRequirement requirement = mock(V1NodeSelectorRequirement.class);
    when(requirement.getKey()).thenReturn("test-key");
    when(requirement.getValues()).thenReturn(List.of("first-value", "second-value"));
    when(requirement.getOperator()).thenReturn("In");

    V1NodeSelectorTerm term = mock(V1NodeSelectorTerm.class);
    when(term.getMatchExpressions()).thenReturn(List.of(requirement));

    Pod pod = mock(Pod.class);
    when(pod.getNodeAffinitySelectorTerms()).thenReturn(List.of(term));

    NodePodBinding nodePodBinding = mock(NodePodBinding.class);
    when(nodePodBinding.getNode()).thenReturn(node);
    when(nodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeAffinity.isVulnerable(nodePodBinding)).isTrue();
  }

  @Test
  public void isVulnerableTwoNodeSelectorsAllExpressionsMatchTest() {
    // Node mock.
    Node node = mock(Node.class);
    when(node.getLabels()).thenReturn(Map.of("first-test-key", "first-value",
        "second-test-key", "second-value",
        "third-test-key", "third-value"));

    // First NodeSelectorTerm mock.
    V1NodeSelectorRequirement firstTermFirstRequirement = mock(V1NodeSelectorRequirement.class);
    when(firstTermFirstRequirement.getKey()).thenReturn("first-test-key");
    when(firstTermFirstRequirement.getValues()).thenReturn(List.of("first-value", "second-value"));
    when(firstTermFirstRequirement.getOperator()).thenReturn("In");

    V1NodeSelectorRequirement firstTermSecondRequirement = mock(V1NodeSelectorRequirement.class);
    when(firstTermSecondRequirement.getKey()).thenReturn("second-test-key");
    when(firstTermSecondRequirement.getValues()).thenReturn(List.of("first-value", "second-value"));
    when(firstTermSecondRequirement.getOperator()).thenReturn("In");

    V1NodeSelectorTerm firstTerm = mock(V1NodeSelectorTerm.class);
    when(firstTerm.getMatchExpressions())
        .thenReturn(List.of(firstTermFirstRequirement, firstTermSecondRequirement));

    // Second NodeSelectorTerm mock - does not match.
    V1NodeSelectorRequirement secondTermFirstRequirement = mock(V1NodeSelectorRequirement.class);
    when(secondTermFirstRequirement.getKey()).thenReturn("first-test-key");
    when(secondTermFirstRequirement.getValues())
        .thenReturn(List.of("non-matching-value", "second-non-matching-value"));
    when(secondTermFirstRequirement.getOperator()).thenReturn("In");

    V1NodeSelectorTerm secondTerm = mock(V1NodeSelectorTerm.class);
    when(secondTerm.getMatchExpressions()).thenReturn(List.of(secondTermFirstRequirement));

    // Pod mock.
    Pod pod = mock(Pod.class);
    when(pod.getNodeAffinitySelectorTerms()).thenReturn(List.of(firstTerm, secondTerm));

    NodePodBinding nodePodBinding = mock(NodePodBinding.class);
    when(nodePodBinding.getNode()).thenReturn(node);
    when(nodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeAffinity.isVulnerable(nodePodBinding)).isFalse();
  }

  @Test
  public void isVulnerableTwoNodeSelectorsNoExpressionsMatchTest() {
    // Node mock.
    Node node = mock(Node.class);
    when(node.getLabels()).thenReturn(Map.of("first-test-key", "first-value",
        "second-test-key", "second-value",
        "third-test-key", "third-value"));

    // First NodeSelectorTerm mock.
    V1NodeSelectorRequirement firstTermFirstRequirement = mock(V1NodeSelectorRequirement.class);
    when(firstTermFirstRequirement.getKey()).thenReturn("first-test-key");
    when(firstTermFirstRequirement.getValues())
        .thenReturn(List.of("first-value-non-matching", "second-value-non-matching"));
    when(firstTermFirstRequirement.getOperator()).thenReturn("In");

    V1NodeSelectorRequirement firstTermSecondRequirement = mock(V1NodeSelectorRequirement.class);
    when(firstTermSecondRequirement.getKey()).thenReturn("second-test-key");
    when(firstTermSecondRequirement.getValues())
        .thenReturn(List.of("first-value-non-matching", "second-value-non-matching"));
    when(firstTermSecondRequirement.getOperator()).thenReturn("In");

    V1NodeSelectorTerm firstTerm = mock(V1NodeSelectorTerm.class);
    when(firstTerm.getMatchExpressions())
        .thenReturn(List.of(firstTermFirstRequirement, firstTermSecondRequirement));

    // Second NodeSelectorTerm mock - does not match.
    V1NodeSelectorRequirement secondTermFirstRequirement = mock(V1NodeSelectorRequirement.class);
    when(secondTermFirstRequirement.getKey()).thenReturn("first-test-key");
    when(secondTermFirstRequirement.getValues())
        .thenReturn(List.of("non-matching-value", "second-non-matching-value"));
    when(secondTermFirstRequirement.getOperator()).thenReturn("In");

    V1NodeSelectorTerm secondTerm = mock(V1NodeSelectorTerm.class);
    when(secondTerm.getMatchExpressions()).thenReturn(List.of(secondTermFirstRequirement));

    // Pod mock.
    Pod pod = mock(Pod.class);
    when(pod.getNodeAffinitySelectorTerms()).thenReturn(List.of(firstTerm, secondTerm));

    NodePodBinding nodePodBinding = mock(NodePodBinding.class);
    when(nodePodBinding.getNode()).thenReturn(node);
    when(nodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeAffinity.isVulnerable(nodePodBinding)).isTrue();
  }

  @Test
  public void isVulnerableOperatorInMatchesTest() {
    // Node mock.
    Node node = mock(Node.class);
    when(node.getLabels()).thenReturn(Map.of("first-test-key", "first-value",
        "second-test-key", "second-value",
        "third-test-key", "third-value"));

    // First NodeSelectorTerm mock.
    V1NodeSelectorRequirement requirement = mock(V1NodeSelectorRequirement.class);
    when(requirement.getKey()).thenReturn("first-test-key");
    when(requirement.getValues()).thenReturn(List.of("first-value", "second-value", "test-value"));
    when(requirement.getOperator()).thenReturn("In");

    V1NodeSelectorTerm term = mock(V1NodeSelectorTerm.class);
    when(term.getMatchExpressions())
        .thenReturn(List.of(requirement));

    // Pod mock.
    Pod pod = mock(Pod.class);
    when(pod.getNodeAffinitySelectorTerms()).thenReturn(List.of(term));

    NodePodBinding matchingNodePodBinding = mock(NodePodBinding.class);
    when(matchingNodePodBinding.getNode()).thenReturn(node);
    when(matchingNodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeAffinity.isVulnerable(matchingNodePodBinding)).isFalse();
  }

  @Test
  public void isVulnerableOperatorInNotMatchingTest() {
    // Node mock.
    Node node = mock(Node.class);
    when(node.getLabels()).thenReturn(Map.of("first-test-key", "first-value",
        "second-test-key", "second-value",
        "third-test-key", "third-value"));

    // Second NodeSelectorTerm mock - does not match.
    V1NodeSelectorRequirement requirement = mock(V1NodeSelectorRequirement.class);
    when(requirement.getKey()).thenReturn("first-test-key");
    when(requirement.getValues())
        .thenReturn(List.of("non-matching-value", "second-non-matching-value"));
    when(requirement.getOperator()).thenReturn("In");

    V1NodeSelectorTerm term = mock(V1NodeSelectorTerm.class);
    when(term.getMatchExpressions()).thenReturn(List.of(requirement));

    // Pod mock.
    Pod pod = mock(Pod.class);
    when(pod.getNodeAffinitySelectorTerms()).thenReturn(List.of(term));

    NodePodBinding nonMatchingNodePodBinding = mock(NodePodBinding.class);
    when(nonMatchingNodePodBinding.getNode()).thenReturn(node);
    when(nonMatchingNodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeAffinity.isVulnerable(nonMatchingNodePodBinding)).isTrue();
  }

  @Test
  public void isVulnerableOperatorNotInMatchesTest() {
    // Node mock.
    Node node = mock(Node.class);
    when(node.getLabels()).thenReturn(Map.of("first-test-key", "first-value",
        "second-test-key", "second-value",
        "third-test-key", "third-value"));

    // First NodeSelectorTerm mock.
    V1NodeSelectorRequirement requirement = mock(V1NodeSelectorRequirement.class);
    when(requirement.getKey()).thenReturn("first-test-key");
    when(requirement.getValues())
        .thenReturn(List.of("non-matching-first-value", "non-matching-second-value"));
    when(requirement.getOperator()).thenReturn("NotIn");

    V1NodeSelectorTerm term = mock(V1NodeSelectorTerm.class);
    when(term.getMatchExpressions())
        .thenReturn(List.of(requirement));

    // Pod mock.
    Pod pod = mock(Pod.class);
    when(pod.getNodeAffinitySelectorTerms()).thenReturn(List.of(term));

    NodePodBinding matchingNodePodBinding = mock(NodePodBinding.class);
    when(matchingNodePodBinding.getNode()).thenReturn(node);
    when(matchingNodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeAffinity.isVulnerable(matchingNodePodBinding)).isFalse();
  }

  @Test
  public void isVulnerableOperatorNotInNotMatchingTest() {
    // Node mock.
    Node node = mock(Node.class);
    when(node.getLabels()).thenReturn(Map.of("first-test-key", "first-value",
        "second-test-key", "second-value",
        "third-test-key", "third-value"));

    // Second NodeSelectorTerm mock - does not match.
    V1NodeSelectorRequirement requirement = mock(V1NodeSelectorRequirement.class);
    when(requirement.getKey()).thenReturn("first-test-key");
    when(requirement.getValues()).thenReturn(List.of("first-value", "second-value", "test-value"));
    when(requirement.getOperator()).thenReturn("NotIn");

    V1NodeSelectorTerm term = mock(V1NodeSelectorTerm.class);
    when(term.getMatchExpressions()).thenReturn(List.of(requirement));

    // Pod mock.
    Pod pod = mock(Pod.class);
    when(pod.getNodeAffinitySelectorTerms()).thenReturn(List.of(term));

    NodePodBinding nonMatchingNodePodBinding = mock(NodePodBinding.class);
    when(nonMatchingNodePodBinding.getNode()).thenReturn(node);
    when(nonMatchingNodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeAffinity.isVulnerable(nonMatchingNodePodBinding)).isTrue();
  }

  @Test
  public void isVulnerableOperatorExistsMatchesTest() {
    // Node mock.
    Node node = mock(Node.class);
    when(node.getLabels()).thenReturn(Map.of("first-test-key", "first-value",
        "second-test-key", "second-value",
        "third-test-key", "third-value"));

    // First NodeSelectorTerm mock.
    V1NodeSelectorRequirement requirement = mock(V1NodeSelectorRequirement.class);
    when(requirement.getKey()).thenReturn("first-test-key");
    when(requirement.getValues()).thenReturn(Collections.emptyList());
    when(requirement.getOperator()).thenReturn("Exists");

    V1NodeSelectorTerm term = mock(V1NodeSelectorTerm.class);
    when(term.getMatchExpressions())
        .thenReturn(List.of(requirement));

    // Pod mock.
    Pod pod = mock(Pod.class);
    when(pod.getNodeAffinitySelectorTerms()).thenReturn(List.of(term));

    NodePodBinding matchingNodePodBinding = mock(NodePodBinding.class);
    when(matchingNodePodBinding.getNode()).thenReturn(node);
    when(matchingNodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeAffinity.isVulnerable(matchingNodePodBinding)).isFalse();
  }

  @Test
  public void isVulnerableOperatorExistsNotMatchingTest() {
    // Node mock.
    Node node = mock(Node.class);
    when(node.getLabels()).thenReturn(Map.of("second-test-key", "second-value",
        "third-test-key", "third-value"));

    // First NodeSelectorTerm mock.
    V1NodeSelectorRequirement requirement = mock(V1NodeSelectorRequirement.class);
    when(requirement.getKey()).thenReturn("first-test-key");
    when(requirement.getValues()).thenReturn(Collections.emptyList());
    when(requirement.getOperator()).thenReturn("Exists");

    V1NodeSelectorTerm term = mock(V1NodeSelectorTerm.class);
    when(term.getMatchExpressions())
        .thenReturn(List.of(requirement));

    // Pod mock.
    Pod pod = mock(Pod.class);
    when(pod.getNodeAffinitySelectorTerms()).thenReturn(List.of(term));

    NodePodBinding matchingNodePodBinding = mock(NodePodBinding.class);
    when(matchingNodePodBinding.getNode()).thenReturn(node);
    when(matchingNodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeAffinity.isVulnerable(matchingNodePodBinding)).isTrue();
  }

  @Test
  public void isVulnerableOperatorExistMatchesTest() {
    // Node mock.
    Node node = mock(Node.class);
    when(node.getLabels()).thenReturn(Map.of("second-test-key", "second-value",
        "third-test-key", "third-value"));

    // Second NodeSelectorTerm mock - does not match.
    V1NodeSelectorRequirement requirement = mock(V1NodeSelectorRequirement.class);
    when(requirement.getKey()).thenReturn("first-test-key");
    when(requirement.getValues()).thenReturn(Collections.emptyList());
    when(requirement.getOperator()).thenReturn("DoesNotExist");

    V1NodeSelectorTerm term = mock(V1NodeSelectorTerm.class);
    when(term.getMatchExpressions()).thenReturn(List.of(requirement));

    // Pod mock.
    Pod pod = mock(Pod.class);
    when(pod.getNodeAffinitySelectorTerms()).thenReturn(List.of(term));

    NodePodBinding nonMatchingNodePodBinding = mock(NodePodBinding.class);
    when(nonMatchingNodePodBinding.getNode()).thenReturn(node);
    when(nonMatchingNodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeAffinity.isVulnerable(nonMatchingNodePodBinding)).isFalse();
  }

  @Test
  public void isVulnerableOperatorDoesNotExistNotMatchingTest() {
    // Node mock.
    Node node = mock(Node.class);
    when(node.getLabels()).thenReturn(Map.of("first-test-key", "first-value",
        "second-test-key", "second-value",
        "third-test-key", "third-value"));

    // First NodeSelectorTerm mock.
    V1NodeSelectorRequirement requirement = mock(V1NodeSelectorRequirement.class);
    when(requirement.getKey()).thenReturn("first-test-key");
    when(requirement.getValues()).thenReturn(Collections.emptyList());
    when(requirement.getOperator()).thenReturn("DoesNotExist");

    V1NodeSelectorTerm term = mock(V1NodeSelectorTerm.class);
    when(term.getMatchExpressions())
        .thenReturn(List.of(requirement));

    // Pod mock.
    Pod pod = mock(Pod.class);
    when(pod.getNodeAffinitySelectorTerms()).thenReturn(List.of(term));

    NodePodBinding matchingNodePodBinding = mock(NodePodBinding.class);
    when(matchingNodePodBinding.getNode()).thenReturn(node);
    when(matchingNodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeAffinity.isVulnerable(matchingNodePodBinding)).isTrue();
  }

  @Test
  public void isVulnerableOperatorLtMatchesTest() {
    // Node mock.
    Node node = mock(Node.class);
    when(node.getLabels()).thenReturn(Map.of("first-test-key", "5",
        "second-test-key", "second-value",
        "third-test-key", "third-value"));

    // Second NodeSelectorTerm mock - does not match.
    V1NodeSelectorRequirement requirement = mock(V1NodeSelectorRequirement.class);
    when(requirement.getKey()).thenReturn("first-test-key");
    when(requirement.getValues()).thenReturn(List.of("10"));
    when(requirement.getOperator()).thenReturn("Lt");

    V1NodeSelectorTerm term = mock(V1NodeSelectorTerm.class);
    when(term.getMatchExpressions()).thenReturn(List.of(requirement));

    // Pod mock.
    Pod pod = mock(Pod.class);
    when(pod.getNodeAffinitySelectorTerms()).thenReturn(List.of(term));

    NodePodBinding nonMatchingNodePodBinding = mock(NodePodBinding.class);
    when(nonMatchingNodePodBinding.getNode()).thenReturn(node);
    when(nonMatchingNodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeAffinity.isVulnerable(nonMatchingNodePodBinding)).isFalse();
  }

  @Test
  public void isVulnerableOperatorLtNotMatchingTest() {
    // Node mock.
    Node node = mock(Node.class);
    when(node.getLabels()).thenReturn(Map.of("first-test-key", "5",
        "second-test-key", "second-value",
        "third-test-key", "third-value"));

    // Second NodeSelectorTerm mock - does not match.
    V1NodeSelectorRequirement requirement = mock(V1NodeSelectorRequirement.class);
    when(requirement.getKey()).thenReturn("first-test-key");
    when(requirement.getValues()).thenReturn(List.of("0"));
    when(requirement.getOperator()).thenReturn("Lt");

    V1NodeSelectorTerm term = mock(V1NodeSelectorTerm.class);
    when(term.getMatchExpressions())
        .thenReturn(List.of(requirement));

    // Pod mock.
    Pod pod = mock(Pod.class);
    when(pod.getNodeAffinitySelectorTerms()).thenReturn(List.of(term));

    NodePodBinding matchingNodePodBinding = mock(NodePodBinding.class);
    when(matchingNodePodBinding.getNode()).thenReturn(node);
    when(matchingNodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeAffinity.isVulnerable(matchingNodePodBinding)).isTrue();
  }

  @Test
  public void isVulnerableOperatorGtMatchesTest() {
    // Node mock.
    Node node = mock(Node.class);
    when(node.getLabels()).thenReturn(Map.of("first-test-key", "15",
        "second-test-key", "second-value",
        "third-test-key", "third-value"));

    // Second NodeSelectorTerm mock - does not match.
    V1NodeSelectorRequirement requirement = mock(V1NodeSelectorRequirement.class);
    when(requirement.getKey()).thenReturn("first-test-key");
    when(requirement.getValues()).thenReturn(List.of("10"));
    when(requirement.getOperator()).thenReturn("Gt");

    V1NodeSelectorTerm term = mock(V1NodeSelectorTerm.class);
    when(term.getMatchExpressions()).thenReturn(List.of(requirement));

    // Pod mock.
    Pod pod = mock(Pod.class);
    when(pod.getNodeAffinitySelectorTerms()).thenReturn(List.of(term));

    NodePodBinding nonMatchingNodePodBinding = mock(NodePodBinding.class);
    when(nonMatchingNodePodBinding.getNode()).thenReturn(node);
    when(nonMatchingNodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeAffinity.isVulnerable(nonMatchingNodePodBinding)).isFalse();
  }

  @Test
  public void isVulnerableOperatorGtNotMatchingTest() {
    // Node mock.
    Node node = mock(Node.class);
    when(node.getLabels()).thenReturn(Map.of("first-test-key", "5",
        "second-test-key", "second-value",
        "third-test-key", "third-value"));

    // Second NodeSelectorTerm mock - does not match.
    V1NodeSelectorRequirement requirement = mock(V1NodeSelectorRequirement.class);
    when(requirement.getKey()).thenReturn("first-test-key");
    when(requirement.getValues()).thenReturn(List.of("10"));
    when(requirement.getOperator()).thenReturn("Gt");

    V1NodeSelectorTerm term = mock(V1NodeSelectorTerm.class);
    when(term.getMatchExpressions())
        .thenReturn(List.of(requirement));

    // Pod mock.
    Pod pod = mock(Pod.class);
    when(pod.getNodeAffinitySelectorTerms()).thenReturn(List.of(term));

    NodePodBinding matchingNodePodBinding = mock(NodePodBinding.class);
    when(matchingNodePodBinding.getNode()).thenReturn(node);
    when(matchingNodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeAffinity.isVulnerable(matchingNodePodBinding)).isTrue();
  }

  @Test
  public void isVulnerableOperatorGtNonNumericalValueTest() {
    // Node mock.
    Node node = mock(Node.class);
    when(node.getLabels()).thenReturn(Map.of("first-test-key", "first-value",
        "second-test-key", "second-value",
        "third-test-key", "third-value"));

    // Second NodeSelectorTerm mock - does not match.
    V1NodeSelectorRequirement requirement = mock(V1NodeSelectorRequirement.class);
    when(requirement.getKey()).thenReturn("first-test-key");
    when(requirement.getValues()).thenReturn(List.of("10"));
    when(requirement.getOperator()).thenReturn("Gt");

    V1NodeSelectorTerm term = mock(V1NodeSelectorTerm.class);
    when(term.getMatchExpressions())
        .thenReturn(List.of(requirement));

    // Pod mock.
    Pod pod = mock(Pod.class);
    when(pod.getNodeAffinitySelectorTerms()).thenReturn(List.of(term));

    NodePodBinding matchingNodePodBinding = mock(NodePodBinding.class);
    when(matchingNodePodBinding.getNode()).thenReturn(node);
    when(matchingNodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeAffinity.isVulnerable(matchingNodePodBinding)).isTrue();
  }

  @Test
  public void isVulnerableOperatorGtFloatValueTest() {
    // Node mock.
    Node node = mock(Node.class);
    when(node.getLabels()).thenReturn(Map.of("first-test-key", "15.5",
        "second-test-key", "second-value",
        "third-test-key", "third-value"));

    // Second NodeSelectorTerm mock - does not match.
    V1NodeSelectorRequirement requirement = mock(V1NodeSelectorRequirement.class);
    when(requirement.getKey()).thenReturn("first-test-key");
    when(requirement.getValues()).thenReturn(List.of("10"));
    when(requirement.getOperator()).thenReturn("Gt");

    V1NodeSelectorTerm term = mock(V1NodeSelectorTerm.class);
    when(term.getMatchExpressions())
        .thenReturn(List.of(requirement));

    // Pod mock.
    Pod pod = mock(Pod.class);
    when(pod.getNodeAffinitySelectorTerms()).thenReturn(List.of(term));

    NodePodBinding matchingNodePodBinding = mock(NodePodBinding.class);
    when(matchingNodePodBinding.getNode()).thenReturn(node);
    when(matchingNodePodBinding.getPod()).thenReturn(pod);

    assertThat(nodeAffinity.isVulnerable(matchingNodePodBinding)).isTrue();
  }

}
