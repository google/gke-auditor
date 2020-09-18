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
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A test for {@link WildcardUsed}.
 */
public class WildcardUsedTest {

  private WildcardUsed wildcardUsed;

  @BeforeEach
  public void init() {
    wildcardUsed = new WildcardUsed();
  }

  @Test
  public void getRecommendationTextTest() {
    assertThat(wildcardUsed.getRecommendationText()).isNotEmpty();
  }

  @Test
  public void getDetectorNameTest() {
    assertThat(wildcardUsed.getDetectorName()).isNotEmpty();
    assertThat(wildcardUsed.getDetectorName())
        .isEqualTo("WILDCARD_USED");
  }

  @Test
  public void getUsefulURLsTest() {
    List<String> usefulUrls = List.of("https://kubernetes.io/docs/admin/authorization/rbac");

    assertThat(wildcardUsed.getUsefulURLs()).isNotNull();
    assertThat(wildcardUsed.getUsefulURLs()).containsAll(usefulUrls);
  }

  @Test
  public void isVulnerableWildcardUsedInVerbsTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getVerbs()).thenReturn(List.of("get", "list", "*"));
    when(rule.getResources()).thenReturn(List.of("pods", "nodes"));
    when(rule.getApiGroups()).thenReturn(null);
    when(rule.getNonResourceURLs()).thenReturn(Collections.emptyList());
    when(rule.getResourceNames()).thenReturn(List.of("pods", "nodes"));

    KubernetesRole role = mock(KubernetesRole.class);
    when(role.getRules()).thenReturn(List.of(rule));

    assertThat(wildcardUsed.isVulnerable(role)).isTrue();
  }


  @Test
  public void isVulnerableWildcardUsedInResourcesTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getVerbs()).thenReturn(null);
    when(rule.getResources()).thenReturn(List.of("pods", "*"));
    when(rule.getApiGroups()).thenReturn(List.of("api"));
    when(rule.getNonResourceURLs()).thenReturn(Collections.emptyList());
    when(rule.getResourceNames()).thenReturn(List.of("pods", "nodes"));

    KubernetesRole role = mock(KubernetesRole.class);
    when(role.getRules()).thenReturn(List.of(rule));

    assertThat(wildcardUsed.isVulnerable(role)).isTrue();
  }


  @Test
  public void isVulnerableWildcardNotUsedTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getVerbs()).thenReturn(List.of("get", "list"));
    when(rule.getResources()).thenReturn(List.of("pods", "nodes"));
    when(rule.getApiGroups()).thenReturn(null);
    when(rule.getNonResourceURLs()).thenReturn(Collections.emptyList());
    when(rule.getResourceNames()).thenReturn(List.of("pods", "nodes"));

    KubernetesRole role = mock(KubernetesRole.class);
    when(role.getRules()).thenReturn(List.of(rule));

    assertThat(wildcardUsed.isVulnerable(role)).isFalse();
  }

  @Test
  public void isVulnerableNullTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getVerbs()).thenReturn(null);
    when(rule.getResources()).thenReturn(null);
    when(rule.getApiGroups()).thenReturn(null);
    when(rule.getNonResourceURLs()).thenReturn(null);
    when(rule.getResourceNames()).thenReturn(null);

    KubernetesRole role = mock(KubernetesRole.class);
    when(role.getRules()).thenReturn(List.of(rule));

    assertThat(wildcardUsed.isVulnerable(role)).isFalse();
  }

}