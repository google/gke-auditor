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
 * Test for {@link AddedCapabilities}.
 */
public class AddedCapabilitiesTest {

  private AddedCapabilities addedCapabilities;

  @BeforeEach
  public void init() {
    addedCapabilities = new AddedCapabilities();
  }

  @Test
  public void getRecommendationTextTest() {
    assertThat(addedCapabilities.getRecommendationText()).isNotEmpty();
  }

  @Test
  public void getDetectorNameTest() {
    assertThat(addedCapabilities.getDetectorName()).isNotEmpty();
    assertThat(addedCapabilities.getDetectorName()).isEqualTo("CONTAINERS_ADDED_CAPABILITIES");
  }

  @Test
  public void getUsefulURLsTest() {
    List<String> usefulUrls = List
        .of("https://kubernetes.io/docs/concepts/policy/pod-security-policy/#enabling-pod-security-policies",
            "https://kubernetes.io/docs/concepts/policy/pod-security-policy/#capabilities");

    assertThat(addedCapabilities.getUsefulURLs()).isNotNull();
    assertThat(addedCapabilities.getUsefulURLs()).containsAll(usefulUrls);
  }

  @Test
  public void isVulnerableAllowedCapabilitiesNullTest() {
    PodSecurityPolicy psp = mock(PodSecurityPolicy.class);
    when(psp.getAllowedCapabilities()).thenReturn(null);

    assertThat(addedCapabilities.isVulnerable(psp)).isFalse();
  }

  @Test
  public void isVulnerableAllowedCapabilitiesEmptyTest() {
    PodSecurityPolicy psp = mock(PodSecurityPolicy.class);
    when(psp.getAllowedCapabilities()).thenReturn(Collections.emptyList());

    assertThat(addedCapabilities.isVulnerable(psp)).isFalse();
  }

  @Test
  public void isVulnerableAllowedCapabilitiesExistTest() {
    PodSecurityPolicy psp = mock(PodSecurityPolicy.class);
    when(psp.getAllowedCapabilities()).thenReturn(new ArrayList<>(
        List.of("TestCapability, AnotherTestCapability")));

    assertThat(addedCapabilities.isVulnerable(psp)).isTrue();
  }

}