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

/**
 * Severity levels used by the tool.
 */
public enum Severity {
  /**
   * Low severity. Used for detectors with informational findings.
   */
  LOW,
  /**
   * Medium severity. Used for detectors with findings that require attention, but are not
   * necessarily critical.
   */
  MEDIUM,
  /**
   * High severity. Used for detectors with findings that need immediate attention.
   */
  HIGH
}
