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

package com.google.gke.auditor.models;

import com.google.gke.auditor.system.Logger;
import com.google.gke.auditor.system.ResourceType;

/**
 * A resource used by the detectors.
 */
public abstract class Asset {

  /**
   * Returns the asset name.
   */
  public abstract String getAssetName();

  /**
   * Returns the asset {@link ResourceType}.
   */
  public abstract ResourceType getResourceType();

  /**
   * Returns a representation of the Asset in the form of {@link Logger.Builder}.
   */
  public Logger.Builder getReport() {
    return Logger.builder().addMessage(toString(), Logger.Color.RED);
  }

}
