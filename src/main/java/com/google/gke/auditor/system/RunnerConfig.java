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

import com.google.gke.auditor.configs.DetectorConfig;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * A configuration class for running the tool.
 * <p>
 * Controls settings such as: which detectors will be run and in which way, output coloring, output
 * verbosity, inclusion of default K8s assets into the auditing.
 */
public class RunnerConfig {

  /**
   * List of RBAC detectors needed to be run.
   */
  private List<DetectorConfig> rbacDetectors;
  /**
   * List of node isolation detectors needed to be run.
   */
  private List<DetectorConfig> isolationDetectors;
  /**
   * List of PSP detectors needed to be run.
   */
  private List<DetectorConfig> pspDetectors;
  /**
   * If false, runs each detector on all assets. If true, runs all detectors on each asset.
   */
  private Boolean runIndividualAssets;
  /**
   * If true, the tool output is non-verbose.
   */
  private boolean quiet;
  /**
   * If true, the tool output is colored.
   */
  private boolean color;
  /**
   * If true, K8s defaults will be included in the audit.
   */
  private boolean includeDefaults;

  private RunnerConfig() {

  }

  /**
   * Returns true if the output is colored, false otherwise.
   */
  public boolean isOutputColored() {
    return color;
  }

  /**
   * Returns true if the output is non-verbose, false otherwise.
   */
  public boolean isQuiet() {
    return quiet;
  }

  /**
   * Returns true if the K8s defaults should be included in the audit, false otherwise.
   */
  public boolean shouldIncludeDefaults() {
    return includeDefaults;
  }

  /**
   * Returns true if the detectors need to be run on individual assets, false otherwise.
   */
  public boolean getRunIndividualAssets() {
    return this.runIndividualAssets;
  }

  /**
   * Returns all asset types used by the configured detectors.
   */
  public ResourceType[] getAssetTypes() {
    return getAllDetectors()
        .stream()
        .map(DetectorConfig::getAssetFilters)
        .flatMap(Arrays::stream)
        .distinct()
        .toArray(ResourceType[]::new);
  }

  /**
   * Returns a list of RBAC detectors needed to be run.
   */
  public List<DetectorConfig> getRbacDetectors() {
    return rbacDetectors;
  }

  /**
   * Returns a list of node isolation detectors needed to be run.
   */
  public List<DetectorConfig> getIsolationDetectors() {
    return isolationDetectors;
  }

  /**
   * Returns a list of psp detectors needed to be run.
   */
  public List<DetectorConfig> getPspDetectors() {
    return pspDetectors;
  }

  /**
   * Gets a list of all detectors needed to be run.
   * <p>
   * Note: this does not return all supported detectors, rather returns a joined list of detectors
   * requested to be run from each group.
   */
  public List<DetectorConfig> getAllDetectors() {
    return Stream.of(rbacDetectors, isolationDetectors, pspDetectors)
        .flatMap(Collection::stream)
        .collect(Collectors.toList());
  }


  /***
   * Builder class for {@link RunnerConfig}.
   */
  public static class Builder {

    private Set<Integer> rbacIndices;
    private Set<Integer> isolationIndices;
    private Set<Integer> pspIndices;
    private boolean runIndividualAssets;
    private boolean quiet;
    private boolean color;
    private boolean includeDefaults;

    /**
     * Builds and returns a {@link RunnerConfig}.
     */
    public RunnerConfig build() {
      RunnerConfig config = new RunnerConfig();
      config.rbacDetectors = filterDetectors(Detectors.RBAC_DETECTORS, rbacIndices);
      config.isolationDetectors = filterDetectors(Detectors.ISOLATION_DETECTORS, isolationIndices);
      config.pspDetectors = filterDetectors(Detectors.PSP_DETECTORS, pspIndices);
      config.quiet = quiet;
      config.color = color;
      config.includeDefaults = includeDefaults;
      config.runIndividualAssets = runIndividualAssets;
      return config;
    }

    /**
     * Set a list of 1-indexed indices of RBAC detectors to run.
     * @param rbacIndices list of indices for RBAC detectors that need to be run
     * @return this
     */
    public Builder setRbacDetectorIndices(Set<Integer> rbacIndices) {
      this.rbacIndices = rbacIndices;
      return this;
    }

    /**
     * Set a list of 1-indexed indices of isolation detectors to run.
     * @param isolationIndices list of indices for isolation detectors that need to be run
     * @return this
     */
    public Builder setIsolationDetectorIndices(Set<Integer> isolationIndices) {
      this.isolationIndices = isolationIndices;
      return this;
    }

    /**
     * Set a list of 1-indexed indices of PSP detectors to run
     * @param pspIndices list of indices for PSP detectors that need to be run
     * @return this
     */
    public Builder setPspDetectorIndices(Set<Integer> pspIndices) {
      this.pspIndices = pspIndices;
      return this;
    }

    /**
     * If set to false, runs each detector on all assets. If true, runs all detectors on each
     * asset.
     * @param runIndividualAssets if true, the tool will be run on each asset individually
     * @return this
     */
    public Builder setRunIndividualAssets(boolean runIndividualAssets) {
      this.runIndividualAssets = runIndividualAssets;
      return this;
    }

    /**
     * If set to true, the auditor output is non-verbose.
     * @param quiet if true, the output is non-verbose
     * @return this
     */
    public Builder setQuiet(boolean quiet) {
      this.quiet = quiet;
      return this;
    }

    /**
     * If set to true, the auditor output is colored.
     * @param color if true, the output is colored
     * @return this
     */
    public Builder setColor(boolean color) {
      this.color = color;
      return this;
    }

    /**
     * If set to true, the tool includes default K8s assets into the audit.
     * @param includeDefaults true if defaults need to be included, false otherwise
     * @return this
     */
    public Builder setIncludeDefaults(boolean includeDefaults) {
      this.includeDefaults = includeDefaults;
      return this;
    }

    /**
     * Filters the list of detector according to the list of given indices (1-indexed). If indices
     * are null, returns all detectors.
     * @param detectors detectors that need to be filtered.
     * @param indices   list of 1-indexed indices of detectors that need to be filtered
     * @return list of filtered detectors
     */
    private List<DetectorConfig> filterDetectors(List<DetectorConfig> detectors,
        Set<Integer> indices) {
      if (indices == null) {
        return detectors;
      }

      List<DetectorConfig> filteredDetectors = new ArrayList<>();
      for (int i : indices) {
        // Indices are 1-indexed.
        if (i > 0 && i <= detectors.size()) {
          filteredDetectors.add(detectors.get(i - 1));
        }
      }
      return filteredDetectors;
    }

  }

}
