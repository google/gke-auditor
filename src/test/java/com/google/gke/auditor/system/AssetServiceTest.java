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

package com.google.gke.auditor.system;

import static org.assertj.core.api.Assertions.assertThat;

import io.kubernetes.client.util.ClientBuilder;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import org.junit.Before;
import org.junit.jupiter.api.Test;

/**
 * A test for {@link AssetService}. Needs proper authorization for API communication before running,
 * see the README.
 */
public class AssetServiceTest {

  @Before
  public void setup() {
    AssetService.client = new ClientBuilder().setBasePath("http://localhost:" + 8384).build();

    AssetService.init(true);
    AssetService.initResourceFetchFunctionMap();
  }

  @Test
  public void generateDependenciesNullTest() {
    assertThat(AssetService.generateDependencies(null, null, null, null)).isEmpty();
  }

  @Test
  public void generateDependenciesEmptyTest() {
    assertThat(AssetService.generateDependencies(Collections.emptyList(), Collections.emptyList(),
        Collections.emptyList(), Collections.emptyList())).isEmpty();
  }

  @Test
  public void getAssetsCacheTest() {
    AssetService.getAssets(new ResourceType[]{ResourceType.CLUSTER_ROLE, ResourceType.ROLE});
    assertThat(AssetService.getResources())
        .containsKeys(ResourceType.CLUSTER_ROLE, ResourceType.ROLE);
  }

  @Test
  public void getAssetsNullTest() {
    AssetService.getAssets(new ResourceType[]{null, ResourceType.CLUSTER_ROLE, ResourceType.NODE});
    assertThat(AssetService.getResources())
        .containsKeys(ResourceType.CLUSTER_ROLE, ResourceType.NODE);
  }

  @Test
  public void getAssetsDefaultsTest() {
    HashSet<String> defaultServiceAccounts = new HashSet<>(Arrays.asList(
        "kube-system/kube-dns-autoscaler",
        "kube-system/metrics-server",
        "kube-system/fluentd-gcp-scaler",
        "kube-system/heapster",
        "kube-system/metadata-agent"));

    assertThat(AssetService.getAssets(new ResourceType[]{ResourceType.SERVICE_ACCOUNT})
        .containsAll(defaultServiceAccounts));
  }

  @Test
  public void getAssetsNoDefaultsTest() {
    AssetService.init(false);
    HashSet<String> defaultServiceAccounts = new HashSet<>(Arrays.asList(
        "kube-system/kube-dns-autoscaler",
        "kube-system/metrics-server",
        "kube-system/fluentd-gcp-scaler",
        "kube-system/heapster",
        "kube-system/metadata-agent"));

    assertThat(!AssetService.getAssets(new ResourceType[]{ResourceType.SERVICE_ACCOUNT})
        .containsAll(defaultServiceAccounts));
  }

}
