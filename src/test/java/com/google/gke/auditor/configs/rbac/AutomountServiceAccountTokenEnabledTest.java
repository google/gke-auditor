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

import com.google.gke.auditor.models.ServiceAccount;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Test for {@link AutomountServiceAccountTokenEnabled}.
 */
public class AutomountServiceAccountTokenEnabledTest {

  private AutomountServiceAccountTokenEnabled automountServiceAccountTokenEnabled;

  @BeforeEach
  public void init() {
    automountServiceAccountTokenEnabled = new AutomountServiceAccountTokenEnabled();
  }

  @Test
  public void getRecommendationTextTest() {
    assertThat(automountServiceAccountTokenEnabled.getRecommendationText()).isNotEmpty();
  }

  @Test
  public void getDetectorNameTest() {
    assertThat(automountServiceAccountTokenEnabled.getDetectorName()).isNotEmpty();
    assertThat(automountServiceAccountTokenEnabled.getDetectorName())
        .isEqualTo("AUTOMOUNT_SERVICE_ACCOUNT_TOKENS_ENABLED");
  }

  @Test
  public void getUsefulURLsTest() {
    List<String> usefulUrls = List
        .of("https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/");

    assertThat(automountServiceAccountTokenEnabled.getUsefulURLs()).isNotNull();
    assertThat(automountServiceAccountTokenEnabled.getUsefulURLs()).containsAll(usefulUrls);
  }

  @Test
  public void isVulnerableAutomountServiceAccountTokenTrueTest() {
    ServiceAccount serviceAccount = mock(ServiceAccount.class);
    when(serviceAccount.getAutomountServiceAccountToken()).thenReturn(true);

    assertThat(automountServiceAccountTokenEnabled.isVulnerable(serviceAccount)).isTrue();
  }

  @Test
  public void isVulnerableAutomountServiceAccountTokenFalseTest() {
    ServiceAccount serviceAccount = mock(ServiceAccount.class);
    when(serviceAccount.getAutomountServiceAccountToken()).thenReturn(false);

    assertThat(automountServiceAccountTokenEnabled.isVulnerable(serviceAccount)).isFalse();
  }

}