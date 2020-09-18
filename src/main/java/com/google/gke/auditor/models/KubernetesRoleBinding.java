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
import io.kubernetes.client.openapi.models.V1beta1RoleRef;
import io.kubernetes.client.openapi.models.V1beta1Subject;
import java.util.List;

/**
 * An abstract representation of a K8s Binding asset (either {@link ClusterRoleBinding} or {@link
 * RoleBinding});
 * <p>
 * Grants the permissions defined in a {@link KubernetesRole} to a user or a set of users. Holds a
 * list of subjects and a reference to the role being granted.
 */
public abstract class KubernetesRoleBinding extends Asset {

  /**
   * Returns a list of {@link V1beta1Subject}s of the role binding.
   */
  public abstract List<V1beta1Subject> getSubjects();

  /**
   * Returns the {@link V1beta1RoleRef}s of the role binding.
   */
  public abstract V1beta1RoleRef getRoleRef();

  /**
   * Returns the role reference name of the role binding.
   */
  public abstract String getRoleRefName();

  @Override
  public Builder getReport() {
    Logger.Builder roleRefBuilder = Logger.builder();
    roleRefBuilder.addMessage("RoleRef", "", Color.RED);

    roleRefBuilder.addSubMessage("ApiGroup", getRoleRef().getApiGroup(), Color.RED);
    roleRefBuilder.addSubMessage("Kind", getRoleRef().getKind(), Color.RED);
    roleRefBuilder.addSubMessage("Name", getRoleRefName(), Color.RED);

    Logger.Builder subjectBuilder = Logger.builder();
    for (V1beta1Subject subject : getSubjects()) {
      subjectBuilder.addMessage("Subject", "", Color.RED);
      subjectBuilder.addSubMessage("ApiGroup", subject.getApiGroup(), Color.RED);
      subjectBuilder.addSubMessage("Kind", subject.getKind(), Color.RED);
      subjectBuilder.addSubMessage("Name", subject.getName(), Color.RED);
      if (subject.getNamespace() != null) {
        subjectBuilder.addSubMessage("Namespace", subject.getNamespace(), Color.RED);
      }
    }

    return Logger.builder()
        .addSubMessages(roleRefBuilder)
        .addSubMessages(subjectBuilder);
  }

}
