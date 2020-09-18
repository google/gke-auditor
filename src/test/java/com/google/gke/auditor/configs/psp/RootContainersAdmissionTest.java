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

package com.google.gke.auditor.configs.psp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.gke.auditor.models.PodSecurityPolicy;
import io.kubernetes.client.openapi.models.PolicyV1beta1IDRange;
import io.kubernetes.client.openapi.models.PolicyV1beta1RunAsUserStrategyOptions;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A test for {@link RootContainersAdmission}.
 */
public class RootContainersAdmissionTest {

  private RootContainersAdmission rootContainersAdmission;

  @BeforeEach
  public void init() {
    rootContainersAdmission = new RootContainersAdmission();
  }

  @Test
  public void getRecommendationTextTest() {
    assertThat(rootContainersAdmission.getRecommendationText()).isNotEmpty();
  }

  @Test
  public void getDetectorNameTest() {
    assertThat(rootContainersAdmission.getDetectorName()).isNotEmpty();
    assertThat(rootContainersAdmission.getDetectorName())
        .isEqualTo("ROOT_CONTAINERS_ADMISSION");
  }

  @Test
  public void getUsefulURLsTest() {
    List<String> usefulUrls = List
        .of("https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems",
            "https://kubernetes.io/docs/concepts/policy/pod-security-policy/#users-and-groups");

    assertThat(rootContainersAdmission.getUsefulURLs()).isNotNull();
    assertThat(rootContainersAdmission.getUsefulURLs()).containsAll(usefulUrls);
  }

  @Test
  public void isVulnerableRunAsUserNullTest() {
    PodSecurityPolicy psp = mock(PodSecurityPolicy.class);
    when(psp.getRunAsUser()).thenReturn(null);

    assertThat(rootContainersAdmission.isVulnerable(psp)).isFalse();
  }

  @Test
  public void isVulnerableRunAsAnyTest() {
    PolicyV1beta1RunAsUserStrategyOptions runAsUser = mock(
        PolicyV1beta1RunAsUserStrategyOptions.class);
    when(runAsUser.getRule()).thenReturn("RunAsAny");

    PodSecurityPolicy psp = mock(PodSecurityPolicy.class);
    when(psp.getRunAsUser()).thenReturn(runAsUser);

    assertThat(rootContainersAdmission.isVulnerable(psp)).isTrue();
  }

  @Test
  public void isVulnerableMustRunAsNonRootTest() {
    PolicyV1beta1RunAsUserStrategyOptions runAsUser = mock(
        PolicyV1beta1RunAsUserStrategyOptions.class);
    when(runAsUser.getRule()).thenReturn("MustRunAsNonRoot");

    PodSecurityPolicy psp = mock(PodSecurityPolicy.class);
    when(psp.getRunAsUser()).thenReturn(runAsUser);

    assertThat(rootContainersAdmission.isVulnerable(psp)).isFalse();
  }


  @Test
  public void isVulnerableMustRunAsRangeMin0Test() {
    PolicyV1beta1IDRange range = mock(PolicyV1beta1IDRange.class);
    when(range.getMin()).thenReturn(0L);
    PolicyV1beta1RunAsUserStrategyOptions runAsUser = mock(
        PolicyV1beta1RunAsUserStrategyOptions.class);
    when(runAsUser.getRule()).thenReturn("MustRunAs");
    when(runAsUser.getRanges()).thenReturn(List.of(range));

    PodSecurityPolicy psp = mock(PodSecurityPolicy.class);
    when(psp.getRunAsUser()).thenReturn(runAsUser);

    assertThat(rootContainersAdmission.isVulnerable(psp)).isTrue();
  }

  @Test
  public void isVulnerableMustRunAsRangesMinNot0Test() {
    PolicyV1beta1IDRange range = mock(PolicyV1beta1IDRange.class);
    when(range.getMin()).thenReturn(5L);
    PolicyV1beta1RunAsUserStrategyOptions runAsUser = mock(
        PolicyV1beta1RunAsUserStrategyOptions.class);
    when(runAsUser.getRule()).thenReturn("MustRunAs");
    when(runAsUser.getRanges()).thenReturn(List.of(range));

    PodSecurityPolicy psp = mock(PodSecurityPolicy.class);
    when(psp.getRunAsUser()).thenReturn(runAsUser);

    assertThat(rootContainersAdmission.isVulnerable(psp)).isFalse();
  }

  @Test
  public void isVulnerableMustRunAsMultipleRangesNotIncluding0Test() {
    PolicyV1beta1IDRange firstRange = mock(PolicyV1beta1IDRange.class);
    when(firstRange.getMin()).thenReturn(0L);
    PolicyV1beta1IDRange secondRange = mock(PolicyV1beta1IDRange.class);
    when(secondRange.getMin()).thenReturn(5L);

    PolicyV1beta1RunAsUserStrategyOptions runAsUser = mock(
        PolicyV1beta1RunAsUserStrategyOptions.class);
    when(runAsUser.getRule()).thenReturn("MustRunAs");
    when(runAsUser.getRanges()).thenReturn(List.of(firstRange, secondRange));

    PodSecurityPolicy psp = mock(PodSecurityPolicy.class);
    when(psp.getRunAsUser()).thenReturn(runAsUser);

    assertThat(rootContainersAdmission.isVulnerable(psp)).isTrue();
  }

  @Test
  public void isVulnerableMustRunAsMultipleRangesIncluding0Test() {
    PolicyV1beta1IDRange firstRange = mock(PolicyV1beta1IDRange.class);
    when(firstRange.getMin()).thenReturn(10L);
    PolicyV1beta1IDRange secondRange = mock(PolicyV1beta1IDRange.class);
    when(secondRange.getMin()).thenReturn(5L);

    PolicyV1beta1RunAsUserStrategyOptions runAsUser = mock(
        PolicyV1beta1RunAsUserStrategyOptions.class);
    when(runAsUser.getRule()).thenReturn("MustRunAs");
    when(runAsUser.getRanges()).thenReturn(List.of(firstRange, secondRange));

    PodSecurityPolicy psp = mock(PodSecurityPolicy.class);
    when(psp.getRunAsUser()).thenReturn(runAsUser);

    assertThat(rootContainersAdmission.isVulnerable(psp)).isFalse();
  }

}