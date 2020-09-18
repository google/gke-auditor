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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Test for {@link CapabilitiesAssigned}.
 */
public class CapabilitiesAssignedTest {

  private CapabilitiesAssigned capabilitiesAssigned;

  @BeforeEach
  public void init() {
    capabilitiesAssigned = new CapabilitiesAssigned();
  }

  @Test
  public void getRecommendationTextTest() {
    assertThat(capabilitiesAssigned.getRecommendationText()).isNotEmpty();
  }

  @Test
  public void getDetectorNameTest() {
    assertThat(capabilitiesAssigned.getDetectorName()).isNotEmpty();
    assertThat(capabilitiesAssigned.getDetectorName())
        .isEqualTo("CONTAINERS_CAPABILITIES_ASSIGNED");
  }

  @Test
  public void getUsefulURLsTest() {
    List<String> usefulUrls = List
        .of("https://kubernetes.io/docs/concepts/policy/pod-security-policy/#enabling-pod-security-policies",
            "https://kubernetes.io/docs/concepts/policy/pod-security-policy/#capabilities");

    assertThat(capabilitiesAssigned.getUsefulURLs()).isNotNull();
    assertThat(capabilitiesAssigned.getUsefulURLs()).containsAll(usefulUrls);
  }

  @Test
  public void isVulnerableAllowedCapabilitiesNullTest() {
    PodSecurityPolicy psp = mock(PodSecurityPolicy.class);
    when(psp.getRequiredDropCapabilities()).thenReturn(null);

    assertThat(capabilitiesAssigned.isVulnerable(psp)).isTrue();
  }

  @Test
  public void isVulnerableAllowedCapabilitiesEmptyTest() {
    PodSecurityPolicy psp = mock(PodSecurityPolicy.class);
    when(psp.getRequiredDropCapabilities()).thenReturn(Collections.emptyList());

    assertThat(capabilitiesAssigned.isVulnerable(psp)).isTrue();
  }

  @Test
  public void isVulnerableAllowedCapabilitiesExistTest() {
    PodSecurityPolicy psp = mock(PodSecurityPolicy.class);
    when(psp.getRequiredDropCapabilities()).thenReturn(new ArrayList<>(
        List.of("TestCapability, AnotherTestCapability")));

    assertThat(capabilitiesAssigned.isVulnerable(psp)).isTrue();
  }

  @Test
  public void isVulnerableAllowedCapabilitiesAllTest() {
    PodSecurityPolicy psp = mock(PodSecurityPolicy.class);
    when(psp.getRequiredDropCapabilities()).thenReturn(new ArrayList<>(
        List.of("ALL")));

    assertThat(capabilitiesAssigned.isVulnerable(psp)).isFalse();
  }

}
