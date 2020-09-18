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
 * A test for {@link AccessToSecrets}.
 */
public class AccessToSecretsTest {

  private AccessToSecrets accessToSecrets;

  @BeforeEach
  public void init() {
    accessToSecrets = new AccessToSecrets();
  }

  @Test
  public void getRecommendationTextTest() {
    assertThat(accessToSecrets.getRecommendationText()).isNotEmpty();
  }

  @Test
  public void getDetectorNameTest() {
    assertThat(accessToSecrets.getDetectorName()).isNotEmpty();
    assertThat(accessToSecrets.getDetectorName())
        .isEqualTo("ACCESS_TO_SECRETS");
  }

  @Test
  public void getUsefulURLsTest() {
    List<String> usefulUrls = List.of("https://kubernetes.io/docs/concepts/configuration/secret/");

    assertThat(accessToSecrets.getUsefulURLs()).isNotNull();
    assertThat(accessToSecrets.getUsefulURLs()).containsAll(usefulUrls);
  }

  @Test
  public void isVulnerableEscalatingVerbsNoSecretsTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getVerbs()).thenReturn(List.of("watch", "list"));
    when(rule.getResources()).thenReturn(List.of("pods", "nodes"));

    KubernetesRole role = mock(KubernetesRole.class);
    when(role.getRules()).thenReturn(List.of(rule));

    assertThat(accessToSecrets.isVulnerable(role)).isFalse();
  }

  @Test
  public void isVulnerableEscalatingVerbsWithSecretsTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getVerbs()).thenReturn(List.of("get", "watch"));
    when(rule.getResources()).thenReturn(List.of("pods", "nodes", "secrets"));

    KubernetesRole role = mock(KubernetesRole.class);
    when(role.getRules()).thenReturn(List.of(rule));

    assertThat(accessToSecrets.isVulnerable(role)).isTrue();
  }

  @Test
  public void isVulnerableNonEscalatingVerbsWithSecretsTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getVerbs()).thenReturn(Collections.emptyList());
    when(rule.getResources()).thenReturn(List.of("pods", "nodes", "secrets"));

    KubernetesRole role = mock(KubernetesRole.class);
    when(role.getRules()).thenReturn(List.of(rule));

    assertThat(accessToSecrets.isVulnerable(role)).isFalse();
  }

  @Test
  public void isVulnerableVerbsNullTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getVerbs()).thenReturn(null);
    when(rule.getResources()).thenReturn(List.of("pods", "nodes", "secrets"));

    KubernetesRole role = mock(KubernetesRole.class);
    when(role.getRules()).thenReturn(List.of(rule));

    assertThat(accessToSecrets.isVulnerable(role)).isFalse();
  }

  @Test
  public void isVulnerableResourcesNullTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getVerbs()).thenReturn(List.of("get", "list", "watch"));
    when(rule.getResources()).thenReturn(null);

    KubernetesRole role = mock(KubernetesRole.class);
    when(role.getRules()).thenReturn(List.of(rule));

    assertThat(accessToSecrets.isVulnerable(role)).isFalse();
  }

  @Test
  public void isVulnerableResourcesEscalatingVerbsEmptyResourcesTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getVerbs()).thenReturn(List.of("get", "list", "watch"));
    when(rule.getResources()).thenReturn(Collections.emptyList());

    KubernetesRole role = mock(KubernetesRole.class);
    when(role.getRules()).thenReturn(List.of(rule));

    assertThat(accessToSecrets.isVulnerable(role)).isFalse();
  }

}