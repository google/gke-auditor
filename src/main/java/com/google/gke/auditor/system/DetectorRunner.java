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
import com.google.gke.auditor.configs.util.MisconfigurationLevel;
import com.google.gke.auditor.models.Asset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Runs the tool.
 */
public class DetectorRunner {

  /**
   * Runs the auditing according to {@link RunnerConfig} tool configuration.
   * @param config tool configuration
   */
  public static void run(RunnerConfig config) {
    Logger.init(config.isOutputColored(), config.isQuiet());
    AssetService.init(config.shouldIncludeDefaults());

    RunResult result = new RunResult();
    if (config.getRunIndividualAssets()) {
      result.addMisconfigurations(runAssets(config.getAssetTypes(), config.getAllDetectors()));
    } else {
      result.addMisconfigurations(runDetectors(config.getRbacDetectors()));
      result.addMisconfigurations(runDetectors(config.getIsolationDetectors()));
      result.addMisconfigurations(runDetectors(config.getPspDetectors()));
    }
    Logger.logScanningDone(result);
  }

  /**
   * Runs each of the given detectors.
   * @param detectors detectors to run
   */
  public static RunResult runDetectors(List<DetectorConfig> detectors) {
    RunResult result = new RunResult();
    for (DetectorConfig detector : detectors) {
      RunResult tempResult = runDetector(detector);
      result.addMisconfigurations(tempResult);
    }
    return result;
  }

  /**
   * Runs the detector on all possible assets on which the detector operates (determined by the
   * {@link DetectorConfig#getAssetFilters()}.
   * @param detector detector to run
   */
  public static RunResult runDetector(DetectorConfig detector) {
    RunResult result = new RunResult();
    List<Asset> assets = AssetService.getAssets(detector.getAssetFilters());

    List<Logger.Builder> reports = new ArrayList<>();
    for (Asset asset : assets) {
      if (detector.isAssetVulnerable(asset)) {
        result.addMisconfigurations(detector.getMisconfigurationLevel());
        reports.add(asset.getReport());
      }
    }

    Logger.logDetectorResult(detector, reports);
    Logger.logScanningResult(result);
    return result;
  }

  /**
   * Runs the given detectors on each of the assets of type filter.
   * @param detectors detectors to run
   * @param filter    asset type filter
   */
  public static RunResult runAssets(ResourceType[] filter, List<DetectorConfig> detectors) {
    RunResult result = new RunResult();
    for (Asset asset : AssetService.getAssets(filter)) {
      RunResult tempResult = runAsset(asset, detectors);
      result.addMisconfigurations(tempResult);
    }
    return result;
  }

  /**
   * Runs the given detectors on the asset.
   * @param detectors detectors to run
   * @param asset     to run the detectors on
   */
  private static RunResult runAsset(Asset asset, List<DetectorConfig> detectors) {
    RunResult result = new RunResult();
    StringBuilder stringBuilder = new StringBuilder("\nVulnerabilities:\n");

    for (DetectorConfig detector : detectors) {
      List<ResourceType> filters = Arrays.asList(detector.getAssetFilters());
      if (filters.contains(asset.getResourceType())) {
        if (detector.isAssetVulnerable(asset)) {
          stringBuilder.append("\t").append(detector.getDetectorName()).append("\n");
          result.addMisconfigurations(detector.getMisconfigurationLevel());
        }
      }
    }

    if (result.getVulnerabilities() > 0 || result.getWarnings() > 0) {
      Logger.log("\nAsset:\n");
      Logger.log(asset.getReport(), 1);
      Logger.logVulnerability(stringBuilder.toString());
    }
    return result;
  }

  /**
   * Stores auditor run information.
   * <p>
   * Stores information about the number of vulnerabilities and warnings found by an auditor run.
   */
  static class RunResult {

    /**
     * Number of vulnerabilities found.
     */
    private Integer vulnerabilities = 0;
    /**
     * Number of warnings found.
     */
    private Integer warnings = 0;

    /**
     * Gets the number of vulnerabilities found.
     * @return number of vulnerabilities
     */
    public Integer getVulnerabilities() {
      return vulnerabilities;
    }

    /**
     * Gets the number of warnings found.
     * @return number of warnings
     */
    public Integer getWarnings() {
      return warnings;
    }

    /**
     * Adds the given result findings to this result.
     * @param result result to add from
     */
    public void addMisconfigurations(RunResult result) {
      this.vulnerabilities += result.getVulnerabilities();
      this.warnings += result.getWarnings();
    }

    /**
     * Adds a misconfiguration found.
     * @param level level of misconfiguration, either a vulnerability or a warning
     */
    public void addMisconfigurations(MisconfigurationLevel level) {
      addMisconfigurations(level, 1);
    }

    /**
     * Adds the given number of misconfigurations found.
     * @param level  level of misconfiguration, either a vulnerability or a warning
     * @param number number of misconfigurations found
     */
    public void addMisconfigurations(MisconfigurationLevel level, int number) {
      if (level == MisconfigurationLevel.VULNERABILITY) {
        vulnerabilities += number;
      } else {
        warnings += number;
      }
    }

  }

}
