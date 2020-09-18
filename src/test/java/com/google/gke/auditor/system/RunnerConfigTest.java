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
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.google.gke.auditor.system.RunnerConfig.Builder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * A test for {@link RunnerConfig};
 */
public class RunnerConfigTest {

  @Test
  public void filterDetectorsTest() {
    RunnerConfig config = new Builder().setIsolationDetectorIndices(Set.of(1, 2, 3))
        .setRbacDetectorIndices(Collections.emptySet())
        .setPspDetectorIndices(null)
        .build();

    assertEquals(3 + Detectors.PSP_DETECTORS.size(), config.getAllDetectors().size());
    assertEquals(0, config.getRbacDetectors().size());
    assertEquals(3, config.getIsolationDetectors().size());
    assertEquals(Detectors.PSP_DETECTORS.size(), config.getPspDetectors().size());
  }

  @Test
  public void filterDetectorsNullTest() {
    RunnerConfig config = new Builder().setIsolationDetectorIndices(null)
        .setRbacDetectorIndices(null)
        .setPspDetectorIndices(null)
        .build();

    assertEquals(Detectors.PSP_DETECTORS.size() + Detectors.RBAC_DETECTORS.size()
        + Detectors.ISOLATION_DETECTORS.size(), config.getAllDetectors().size());

  }

  @Test
  public void filterDetectorsInvalidIndicesTest() {
    RunnerConfig config = new Builder().setIsolationDetectorIndices(Set.of(0, 1, 2, 3))
        .setRbacDetectorIndices(Set.of(12, 13, 14))
        .setPspDetectorIndices(Set.of(-5, -1))
        .build();

    assertEquals(3, config.getAllDetectors().size());
    assertEquals(0, config.getRbacDetectors().size());
    assertEquals(3, config.getIsolationDetectors().size());
    assertEquals(0, config.getPspDetectors().size());
  }

  @Test
  public void getAssetTypesTest() {
    RunnerConfig config = new Builder().setIsolationDetectorIndices(Set.of(1, 2))
        .setRbacDetectorIndices(Set.of(2))
        .setPspDetectorIndices(Set.of(-5, -1))
        .build();

    List<ResourceType> types = new ArrayList<>();
    types.addAll(Arrays.asList(Detectors.ISOLATION_DETECTORS.get(0).getAssetFilters()));
    types.addAll(Arrays.asList(Detectors.ISOLATION_DETECTORS.get(1).getAssetFilters()));
    types.addAll(Arrays.asList(Detectors.RBAC_DETECTORS.get(1).getAssetFilters()));
    assertThat(config.getAssetTypes()).containsAll(types);

  }

}