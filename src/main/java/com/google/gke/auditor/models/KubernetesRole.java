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
import com.google.gke.auditor.system.Logger.Builder;
import com.google.gke.auditor.system.Logger.Color;
import io.kubernetes.client.openapi.models.V1beta1PolicyRule;
import java.util.ArrayList;
import java.util.List;

/**
 * An abstract representation of a K8s Role asset, either {@link ClusterRole} or {@link Role}.
 * Characterized by rules that represent a set of permissions.
 */
public abstract class KubernetesRole extends Asset {

  /**
   * A list of detected vulnerable rules.
   */
  private List<V1beta1PolicyRule> vulnerableRules = new ArrayList<>();

  /**
   * Returns a list of {@link V1beta1PolicyRule}s.
   */
  public abstract List<V1beta1PolicyRule> getRules();

  /**
   * Add detected vulnerable rules.
   */
  public void addVulnerableRules(List<V1beta1PolicyRule> vulnerableRules) {
    this.vulnerableRules.addAll(vulnerableRules);
  }

  @Override
  public Builder getReport() {
    Logger.Builder builder = Logger.builder();
    builder.addMessage("Rules", "", Color.RED);

    Logger.Builder subMessagesBuilder = Logger.builder();
    for (V1beta1PolicyRule rule : vulnerableRules) {
      if (rule.getApiGroups() != null && !rule.getApiGroups().isEmpty()) {
        subMessagesBuilder.addMessage("ApiGroups", rule.getApiGroups().toString(), Color.RED);
      }
      if (rule.getVerbs() != null && !rule.getVerbs().isEmpty()) {
        subMessagesBuilder.addMessage("Verbs", rule.getVerbs().toString(), Color.RED);
      }
      if (rule.getResources() != null && !rule.getResources().isEmpty()) {
        subMessagesBuilder.addMessage("Resources", rule.getResources().toString(), Color.RED);
      }
      if (rule.getResourceNames() != null && !rule.getResourceNames().isEmpty()) {
        subMessagesBuilder
            .addMessage("Resource names", rule.getResourceNames().toString(), Color.RED);
      }
      if (rule.getNonResourceURLs() != null && !rule.getNonResourceURLs().isEmpty()) {
        subMessagesBuilder.addMessage("Non Resource URLs", rule.getNonResourceURLs().toString(),
            Color.RED);
      }
      subMessagesBuilder.addLineBreak();
    }
    vulnerableRules.clear();
    builder.addSubMessages(subMessagesBuilder);
    return builder;
  }

}
