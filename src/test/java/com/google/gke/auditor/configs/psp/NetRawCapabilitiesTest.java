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
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A test for {@link NetRawCapabilities}.
 */
public class NetRawCapabilitiesTest {

  private NetRawCapabilities netRawCapabilities;

  @BeforeEach
  public void init() {
    netRawCapabilities = new NetRawCapabilities();
  }

  @Test
  public void getRecommendationTextTest() {
    assertThat(netRawCapabilities.getRecommendationText()).isNotEmpty();
  }

  @Test
  public void getDetectorNameTest() {
    assertThat(netRawCapabilities.getDetectorName()).isNotEmpty();
    assertThat(netRawCapabilities.getDetectorName())
        .isEqualTo("CONTAINERS_NET_RAW_CAPABILITIES");
  }

  @Test
  public void getUsefulURLsTest() {
    List<String> usefulUrls = List
        .of("https://kubernetes.io/docs/concepts/policy/pod-security-policy/#enabling-pod-security-policies",
            "https://kubernetes.io/docs/concepts/policy/pod-security-policy/#capabilities");

    assertThat(netRawCapabilities.getUsefulURLs()).isNotNull();
    assertThat(netRawCapabilities.getUsefulURLs()).containsAll(usefulUrls);
  }

  @Test
  public void isVulnerableAllowedCapabilitiesNullTest() {
    PodSecurityPolicy psp = mock(PodSecurityPolicy.class);
    when(psp.getRequiredDropCapabilities()).thenReturn(null);

    assertThat(netRawCapabilities.isVulnerable(psp)).isFalse();
  }

  @Test
  public void isVulnerableDropCapabilitiesDoNotIncludeNetRawTest() {
    PodSecurityPolicy psp = mock(PodSecurityPolicy.class);
    when(psp.getRequiredDropCapabilities())
        .thenReturn(List.of("TestCapability, AnotherTestCapability"));

    assertThat(netRawCapabilities.isVulnerable(psp)).isTrue();
  }

  @Test
  public void isVulnerableDropCapabilitiesIncludeNetRawTest() {
    PodSecurityPolicy psp = mock(PodSecurityPolicy.class);
    when(psp.getRequiredDropCapabilities()).thenReturn(List.of("NET_RAW", "TestCapability"));

    assertThat(netRawCapabilities.isVulnerable(psp)).isFalse();
  }

  @Test
  public void isVulnerableDropCapabilitiesIncludeAllTest() {
    PodSecurityPolicy psp = mock(PodSecurityPolicy.class);
    when(psp.getRequiredDropCapabilities()).thenReturn(List.of("ALL", "TestCapability"));

    assertThat(netRawCapabilities.isVulnerable(psp)).isFalse();
  }

}