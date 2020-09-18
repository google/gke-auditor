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

import com.google.gke.auditor.models.Dependency;
import com.google.gke.auditor.models.KubernetesRole;
import io.kubernetes.client.openapi.models.V1beta1PolicyRule;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A test for {@link EscalatingResourcesDependencyReport}.
 */
public class EscalatingResourcesDependencyReportTest {

  private EscalatingResourcesDependencyReport escalatingResourcesDependencyReport;

  @BeforeEach
  public void init() {
    escalatingResourcesDependencyReport = new EscalatingResourcesDependencyReport();
  }

  @Test
  public void getRecommendationTextTest() {
    assertThat(escalatingResourcesDependencyReport.getRecommendationText()).isNotEmpty();
  }

  @Test
  public void getDetectorNameTest() {
    assertThat(escalatingResourcesDependencyReport.getDetectorName()).isNotEmpty();
    assertThat(escalatingResourcesDependencyReport.getDetectorName())
        .isEqualTo("ESCALATING_RESOURCES_DEPENDENCY_REPORT");
  }

  @Test
  public void getUsefulURLsTest() {
    List<String> usefulUrls = List
        .of("https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/");

    assertThat(escalatingResourcesDependencyReport.getUsefulURLs()).isNotNull();
    assertThat(escalatingResourcesDependencyReport.getUsefulURLs()).containsAll(usefulUrls);
  }

  @Test
  public void isVulnerableDependencyNullTest() {
    assertThat(escalatingResourcesDependencyReport.isVulnerable(null)).isFalse();
  }

  @Test
  public void isVulnerableNullTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getVerbs()).thenReturn(null);
    when(rule.getResources()).thenReturn(null);
    when(rule.getApiGroups()).thenReturn(null);

    KubernetesRole role = mock(KubernetesRole.class);
    when(role.getRules()).thenReturn(List.of(rule));

    Dependency dependency = mock(Dependency.class);
    when(dependency.getRole()).thenReturn(role);

    assertThat(escalatingResourcesDependencyReport.isVulnerable(dependency)).isFalse();
  }

  @Test
  public void isVulnerableHasEscalatingResourcesTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getVerbs()).thenReturn(List.of("get", "list"));
    when(rule.getResources()).thenReturn(List.of("*", "nodes", "secrets"));
    when(rule.getApiGroups()).thenReturn(List.of("api"));

    KubernetesRole role = mock(KubernetesRole.class);
    when(role.getRules()).thenReturn(List.of(rule));

    Dependency dependency = mock(Dependency.class);
    when(dependency.getRole()).thenReturn(role);

    assertThat(escalatingResourcesDependencyReport.isVulnerable(dependency)).isFalse();
  }

  @Test
  public void isVulnerableNoEscalatingResourcesTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getVerbs()).thenReturn(List.of("get", "list"));
    when(rule.getResources()).thenReturn(List.of("nodes", "secrets"));
    when(rule.getApiGroups()).thenReturn(List.of("api"));

    KubernetesRole role = mock(KubernetesRole.class);
    when(role.getRules()).thenReturn(List.of(rule));

    Dependency dependency = mock(Dependency.class);
    when(dependency.getRole()).thenReturn(role);

    assertThat(escalatingResourcesDependencyReport.isVulnerable(dependency)).isFalse();
  }

  @Test
  public void isVulnerableEscalatingVerbsTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getVerbs()).thenReturn(List.of("get", "create", "edit", "list"));
    when(rule.getResources()).thenReturn(List.of("resource", "other/resource"));
    when(rule.getApiGroups()).thenReturn(List.of("api"));

    KubernetesRole role = mock(KubernetesRole.class);
    when(role.getRules()).thenReturn(List.of(rule));

    Dependency dependency = mock(Dependency.class);
    when(dependency.getRole()).thenReturn(role);

    assertThat(escalatingResourcesDependencyReport.isVulnerable(dependency)).isFalse();
  }

  @Test
  public void isVulnerableEscalatingVerbsAndResourcesTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getVerbs()).thenReturn(List.of("get", "create", "edit", "list"));
    when(rule.getResources()).thenReturn(List.of("*", "roles"));
    when(rule.getApiGroups()).thenReturn(List.of("nodes", "rbac.authorization.k8s.io"));

    KubernetesRole role = mock(KubernetesRole.class);
    when(role.getRules()).thenReturn(List.of(rule));

    Dependency dependency = mock(Dependency.class);
    when(dependency.getRole()).thenReturn(role);

    assertThat(escalatingResourcesDependencyReport.isVulnerable(dependency)).isTrue();
  }

  @Test
  public void isVulnerableEmptyVerbsAndResourcesTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getVerbs()).thenReturn(Collections.emptyList());
    when(rule.getResources()).thenReturn(Collections.emptyList());
    when(rule.getApiGroups()).thenReturn(Collections.emptyList());

    KubernetesRole role = mock(KubernetesRole.class);
    when(role.getRules()).thenReturn(List.of(rule));

    Dependency dependency = mock(Dependency.class);
    when(dependency.getRole()).thenReturn(role);

    assertThat(escalatingResourcesDependencyReport.isVulnerable(dependency)).isFalse();
  }

  @Test
  public void isVulnerableEscalatingPrivilegesOnWriteNoEscalatingVerbsTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getVerbs()).thenReturn(List.of("get", "list"));
    when(rule.getResources()).thenReturn(List.of("deployments", "*", "serviceaccounts"));
    when(rule.getApiGroups()).thenReturn(List.of("apps", "extensions"));

    KubernetesRole role = mock(KubernetesRole.class);
    when(role.getRules()).thenReturn(List.of(rule));

    Dependency dependency = mock(Dependency.class);
    when(dependency.getRole()).thenReturn(role);

    assertThat(escalatingResourcesDependencyReport.isVulnerable(dependency)).isFalse();
  }

  @Test
  public void isVulnerableEscalatingPrivilegesOnWriteEscalatingVerbsTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getVerbs()).thenReturn(List.of("create", "list", "edit"));
    when(rule.getResources()).thenReturn(List.of("deployments", "*", "serviceaccounts"));
    when(rule.getApiGroups()).thenReturn(List.of("apps", "extensions"));

    KubernetesRole role = mock(KubernetesRole.class);
    when(role.getRules()).thenReturn(List.of(rule));

    Dependency dependency = mock(Dependency.class);
    when(dependency.getRole()).thenReturn(role);

    assertThat(escalatingResourcesDependencyReport.isVulnerable(dependency)).isTrue();
  }

  @Test
  public void isVulnerableEscalatingSubresourcesNoEscalatingVerbsTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getVerbs()).thenReturn(List.of("list", "get"));
    when(rule.getResources()).thenReturn(List.of("deployments/proxy", "serviceaccounts/attach"));
    when(rule.getApiGroups()).thenReturn(List.of("apps", "extensions"));

    KubernetesRole role = mock(KubernetesRole.class);
    when(role.getRules()).thenReturn(List.of(rule));

    Dependency dependency = mock(Dependency.class);
    when(dependency.getRole()).thenReturn(role);

    assertThat(escalatingResourcesDependencyReport.isVulnerable(dependency)).isFalse();
  }

  @Test
  public void isVulnerableEscalatingSubresourcesEscalatingVerbsTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getVerbs()).thenReturn(List.of("list", "edit", "delete"));
    when(rule.getResources()).thenReturn(List.of("deployments/proxy", "serviceaccounts/attach"));
    when(rule.getApiGroups()).thenReturn(List.of("apps", "extensions"));

    KubernetesRole role = mock(KubernetesRole.class);
    when(role.getRules()).thenReturn(List.of(rule));

    Dependency dependency = mock(Dependency.class);
    when(dependency.getRole()).thenReturn(role);

    assertThat(escalatingResourcesDependencyReport.isVulnerable(dependency)).isTrue();
  }

}