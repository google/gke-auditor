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

import static java.util.Objects.isNull;

import com.google.gke.auditor.configs.util.MisconfigurationLevel;
import com.google.gke.auditor.configs.util.Severity;
import com.google.gke.auditor.models.Asset;
import com.google.gke.auditor.system.Logger;
import com.google.gke.auditor.system.Logger.Builder;
import com.google.gke.auditor.system.Logger.Color;
import com.google.gke.auditor.system.ResourceType;
import java.util.List;

/**
 * Interface for detectors that operate on {@link Asset} instances in search for misconfigurations.
 */
public interface DetectorConfig {

  /**
   * Returns the name of the detector.
   */
  String getDetectorName();

  /**
   * Returns the {@link ResourceType} checked by the detector.
   * <p>
   * Used when the detector operates on a singular {@link ResourceType}.
   */
  ResourceType getAssetFilter();

  /**
   * Returns an array of {@link ResourceType}s checked by the detector.
   * <p>
   * Used when the detector operates on multiple {@link ResourceType}s.
   */
  default ResourceType[] getAssetFilters() {
    return new ResourceType[]{getAssetFilter()};
  }

  /**
   * Returns the {@link MisconfigurationLevel} of the detector.
   */
  MisconfigurationLevel getMisconfigurationLevel();

  /**
   * Returns the {@link Severity} of the vulnerability detected by the detector.
   */
  Severity getSeverity();

  /**
   * Returns an explanation for why the findings created by the Detector constitute a security
   * risk.
   */
  String getExplanationText();

  /**
   * Returns a recommendation to the user for remediating the vulnerability detected by the
   * detector.
   */
  String getRecommendationText();

  /**
   * Returns a list of useful URLs that users can visit to learn about vulnerabilities detected by
   * the detector.
   */
  List<String> getUsefulURLs();

  /**
   * Returns True if the given {@link Asset} has the vulnerability the detector is searching for.
   * This method should not be called directly, use {@link DetectorConfig#isAssetVulnerable(Asset)}
   * instead!
   */
  Boolean isVulnerable(Asset asset);

  /**
   * Returns False if the given {@link Asset} is null or does not have the vulnerability the
   * detector is searching for, True otherwise.
   */
  default Boolean isAssetVulnerable(Asset asset) {
    if (isNull(asset)) {
      return false;
    }
    return isVulnerable(asset);
  }

  /**
   * Returns a {@link Logger.Builder} representation of the detector.
   */
  default Logger.Builder getReport(boolean quiet) {
    Builder builder = new Logger.Builder().addMessage("Detector", getDetectorName());
    if (!quiet) {
      builder.addSubMessage("Explanation", getExplanationText())
          .addSubMessage("Remediation", getRecommendationText())
          .addSubMessage("Useful links", getUsefulURLs().toString())
          .addSubMessage("Level", getMisconfigurationLevel().name())
          .addSubMessage("Severity", getSeverity().name(),
              getSeverity().equals(Severity.MEDIUM) || getSeverity().equals(Severity.LOW)
                  ? Color.DEFAULT : Color.RED);
    }
    return builder;
  }

}

