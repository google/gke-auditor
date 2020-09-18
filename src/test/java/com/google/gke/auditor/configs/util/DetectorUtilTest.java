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

package com.google.gke.auditor.configs.util;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.kubernetes.client.openapi.models.V1beta1PolicyRule;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;

public class DetectorUtilTest {

  @Test
  public void getApiGroupResourcesTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getResources()).thenReturn(List.of("deployments", "*", "serviceaccounts"));
    when(rule.getApiGroups()).thenReturn(List.of("apps", "extensions", ""));

    assertThat(DetectorUtil.getAPIGroupResources(rule)).containsAll(
        List.of("apps/deployments", "apps/*", "apps/serviceaccounts",
            "extensions/deployments", "extensions/*", "extensions/serviceaccounts",
            "deployments", "*", "serviceaccounts")
    );
  }

  @Test
  public void getApiGroupResourcesAndApiGroupsEmptyTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getResources()).thenReturn(Collections.emptyList());
    when(rule.getApiGroups()).thenReturn(Collections.emptyList());

    assertThat(DetectorUtil.getAPIGroupResources(rule)).isEmpty();
  }

  @Test
  public void getApiGroupResourcesAndApiGroupsNullTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getResources()).thenReturn(null);
    when(rule.getApiGroups()).thenReturn(null);

    assertThat(DetectorUtil.getAPIGroupResources(rule)).isEmpty();
  }

  @Test
  public void getApiGroupsNullTest() {
    V1beta1PolicyRule rule = mock(V1beta1PolicyRule.class);
    when(rule.getResources()).thenReturn(null);
    when(rule.getApiGroups()).thenReturn(null);

    assertThat(DetectorUtil.getAPIGroupResources(rule)).isEmpty();
  }

  @Test
  public void getApiGroupsRuleNullTest() {
    assertThat(DetectorUtil.getAPIGroupResources(null)).isEmpty();
  }

}
