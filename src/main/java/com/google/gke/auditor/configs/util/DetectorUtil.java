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

import com.google.gke.auditor.models.Asset;
import io.kubernetes.client.openapi.models.V1beta1PolicyRule;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Function;

/**
 * Utility class for common methods shared by the detectors.
 */
public class DetectorUtil {

  /**
   * Retrieves an asset from the given collection such that it satisfies the condition of the asset
   * property fetched with the getAssetProperty function being equal to the given property.
   * @param collection       collection within to search for
   * @param property         property of the asset being searched for
   * @param getAssetProperty function fetching the asset property being checked
   * @return asset satisfying the condition if such exists, null otherwise
   */
  public static Asset getFromCollection(Collection<Asset> collection, String property,
      Function<Asset, String> getAssetProperty) {
    return collection.stream()
        .filter(asset -> getAssetProperty.apply(asset).equals(property))
        .findFirst()
        .orElse(null);
  }

  /**
   * From a given rule, constructs namespaced resources in the format apiGroup/resource from the
   * rule's APIGroups and list of resources the rule applies to.
   * @param rule rule from which to construct resources
   * @return list of apiGroup namespaced resources
   */
  public static List<String> getAPIGroupResources(V1beta1PolicyRule rule) {
    List<String> resources = new ArrayList<>();
    if (rule == null || rule.getApiGroups() == null || rule.getResources() == null) {
      return resources;
    }

    for (String apiGroup : rule.getApiGroups()) {
      for (String resource : rule.getResources()) {
        if (apiGroup.equals("")) {
          resources.add(resource);
        } else {
          String apiResource = String.format("%s/%s", apiGroup, resource);
          resources.add(apiResource);
        }
      }
    }

    return resources;
  }

}
