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
 * A test for {@link SharingHostPIDNamespace}.
 */
public class SharingHostPIDNamespaceTest {

  private SharingHostPIDNamespace sharingHostPIDNamespace;

  @BeforeEach
  public void init() {
    sharingHostPIDNamespace = new SharingHostPIDNamespace();
  }

  @Test
  public void getRecommendationTextTest() {
    assertThat(sharingHostPIDNamespace.getRecommendationText()).isNotEmpty();
  }

  @Test
  public void getDetectorNameTest() {
    assertThat(sharingHostPIDNamespace.getDetectorName()).isNotEmpty();
    assertThat(sharingHostPIDNamespace.getDetectorName())
        .isEqualTo("CONTAINERS_SHARING_HOST_PROCESS_ID_NAMESPACE");
  }

  @Test
  public void getUsefulURLsTest() {
    List<String> usefulUrls = List
        .of("https://kubernetes.io/docs/concepts/policy/pod-security-policy/#enabling-pod-security-policies",
            "https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces");

    assertThat(sharingHostPIDNamespace.getUsefulURLs()).isNotNull();
    assertThat(sharingHostPIDNamespace.getUsefulURLs()).containsAll(usefulUrls);
  }

  @Test
  public void isVulnerableHostIPCFalseTest() {
    PodSecurityPolicy psp = mock(PodSecurityPolicy.class);
    when(psp.getHostPID()).thenReturn(false);

    assertThat(sharingHostPIDNamespace.isVulnerable(psp)).isFalse();
  }

  @Test
  public void isVulnerableHostIPCTrueTest() {
    PodSecurityPolicy psp = mock(PodSecurityPolicy.class);
    when(psp.getHostPID()).thenReturn(true);

    assertThat(sharingHostPIDNamespace.isVulnerable(psp)).isTrue();
  }

}