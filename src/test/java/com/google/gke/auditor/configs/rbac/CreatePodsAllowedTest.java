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

package com.google.gke.auditor.configs.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.gke.auditor.models.KubernetesRole;
import io.kubernetes.client.openapi.models.V1beta1PolicyRule;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A test for {@link CreatePodsAllowed}.
 */
public class CreatePodsAllowedTest {

  private CreatePodsAllowed createPodsAllowed;

  @BeforeEach
  public void init() {
    createPodsAllowed = new CreatePodsAllowed();
  }

  @Test
  public void getRecommendationTextTest() {
    assertThat(createPodsAllowed.getRecommendationText()).isNotEmpty();
  }

  @Test
  public void getDetectorNameTest() {
    assertThat(createPodsAllowed.getDetectorName()).isNotEmpty();
    assertThat(createPodsAllowed.getDetectorName())
        .isEqualTo("CREATE_PODS_ALLOWED");
  }

  @Test
  public void getUsefulURLsTest() {
    List<String> usefulUrls = List.of("https://kubernetes.io/docs/admin/authorization/rbac");

    assertThat(createPodsAllowed.getUsefulURLs()).isNotNull();
    assertThat(createPodsAllowed.getUsefulURLs()).containsAll(usefulUrls);
  }

  @Test
  public void isVulnerableCreateNoPodResourceTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getVerbs()).thenReturn(List.of("get", "list"));
    when(rule.getResources()).thenReturn(List.of("pods", "nodes"));

    KubernetesRole role = mock(KubernetesRole.class);
    when(role.getRules()).thenReturn(List.of(rule));

    assertThat(createPodsAllowed.isVulnerable(role)).isFalse();
  }

  @Test
  public void isVulnerableCreateWithPodResourceTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getVerbs()).thenReturn(List.of("get", "list", "create"));
    when(rule.getResources()).thenReturn(List.of("pods", "nodes", "secrets"));

    KubernetesRole role = mock(KubernetesRole.class);
    when(role.getRules()).thenReturn(List.of(rule));

    assertThat(createPodsAllowed.isVulnerable(role)).isTrue();
  }

  @Test
  public void isVulnerableNoCreateNoPodResourceTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getVerbs()).thenReturn(List.of("get", "list"));
    when(rule.getResources()).thenReturn(List.of("nodes", "secrets"));

    KubernetesRole role = mock(KubernetesRole.class);
    when(role.getRules()).thenReturn(List.of(rule));

    assertThat(createPodsAllowed.isVulnerable(role)).isFalse();
  }

  @Test
  public void isVulnerableVerbsNullTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getVerbs()).thenReturn(null);
    when(rule.getResources()).thenReturn(List.of("pods", "nodes", "secrets"));

    KubernetesRole role = mock(KubernetesRole.class);
    when(role.getRules()).thenReturn(List.of(rule));

    assertThat(createPodsAllowed.isVulnerable(role)).isFalse();
  }

  @Test
  public void isVulnerableResourcesNullTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getVerbs()).thenReturn(List.of("get", "list"));
    when(rule.getResources()).thenReturn(null);

    KubernetesRole role = mock(KubernetesRole.class);
    when(role.getRules()).thenReturn(List.of(rule));

    assertThat(createPodsAllowed.isVulnerable(role)).isFalse();
  }


}