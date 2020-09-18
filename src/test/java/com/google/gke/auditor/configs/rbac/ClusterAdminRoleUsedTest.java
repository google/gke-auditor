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

import com.google.gke.auditor.models.ClusterRoleBinding;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A test for {@link ClusterAdminRoleUsed}.
 */
public class ClusterAdminRoleUsedTest {

  private ClusterAdminRoleUsed clusterAdminRoleUsed;

  @BeforeEach
  public void init() {
    clusterAdminRoleUsed = new ClusterAdminRoleUsed();
  }

  @Test
  public void getRecommendationTextTest() {
    assertThat(clusterAdminRoleUsed.getRecommendationText()).isNotEmpty();
  }

  @Test
  public void getDetectorNameTest() {
    assertThat(clusterAdminRoleUsed.getDetectorName()).isNotEmpty();
    assertThat(clusterAdminRoleUsed.getDetectorName())
        .isEqualTo("CLUSTER_ADMIN_ROLE_USED");
  }

  @Test
  public void getUsefulURLsTest() {
    List<String> usefulUrls = List
        .of("https://kubernetes.io/docs/admin/authorization/rbac/#user-facing-roles");

    assertThat(clusterAdminRoleUsed.getUsefulURLs()).isNotNull();
    assertThat(clusterAdminRoleUsed.getUsefulURLs()).containsAll(usefulUrls);
  }

  @Test
  public void isVulnerableClusterAdminRoleUsedTest() {
    ClusterRoleBinding binding = mock(ClusterRoleBinding.class);
    when(binding.getRoleRefName()).thenReturn("cluster-admin");

    assertThat(clusterAdminRoleUsed.isVulnerable(binding)).isTrue();
  }

  @Test
  public void isVulnerableClusterAdminRoleNotUsedTest() {
    ClusterRoleBinding binding = mock(ClusterRoleBinding.class);
    when(binding.getRoleRefName()).thenReturn("not-cluster-admin");

    assertThat(clusterAdminRoleUsed.isVulnerable(binding)).isFalse();
  }

  @Test
  public void isVulnerableRoleEmptyTest() {
    ClusterRoleBinding binding = mock(ClusterRoleBinding.class);
    when(binding.getRoleRefName()).thenReturn("");

    assertThat(clusterAdminRoleUsed.isVulnerable(binding)).isFalse();
  }

  @Test
  public void isVulnerableNullTest() {
    ClusterRoleBinding binding = mock(ClusterRoleBinding.class);
    when(binding.getRoleRefName()).thenReturn(null);

    assertThat(clusterAdminRoleUsed.isVulnerable(binding)).isFalse();
  }


}