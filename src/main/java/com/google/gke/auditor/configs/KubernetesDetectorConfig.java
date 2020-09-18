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

package com.google.gke.auditor.configs;

import com.google.gke.auditor.configs.util.MisconfigurationLevel;
import com.google.gke.auditor.configs.util.Severity;
import com.google.gke.auditor.system.ResourceType;
import java.util.List;

/**
 * An abstract implementation of {@link DetectorConfig}.
 * <p>
 * Provides default implementations of methods shared by Kubernetes detectors. All Kubernetes
 * detectors should extend this class.
 */
public abstract class KubernetesDetectorConfig implements DetectorConfig {

  @Override
  public List<String> getUsefulURLs() {
    return List.of("https://kubernetes.io/docs/concepts/");
  }

  @Override
  public ResourceType getAssetFilter() {
    return null;
  }

  @Override
  public MisconfigurationLevel getMisconfigurationLevel() {
    return MisconfigurationLevel.VULNERABILITY;
  }

  @Override
  public Severity getSeverity() {
    return Severity.MEDIUM;
  }

}
