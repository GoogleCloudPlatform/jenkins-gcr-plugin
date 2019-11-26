/*
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.jenkins.plugins.containersecurity.client;

import com.google.api.services.binaryauthorization.v1beta1.BinaryAuthorizationScopes;
import com.google.api.services.cloudkms.v1.CloudKMSScopes;
import com.google.api.services.cloudresourcemanager.CloudResourceManagerScopes;
import com.google.api.services.containeranalysis.v1beta1.ContainerAnalysisScopes;
import com.google.common.collect.ImmutableSet;
import com.google.jenkins.plugins.credentials.oauth.GoogleOAuth2ScopeRequirement;
import java.util.Collection;

/**
 * Defines the set of OAuth2 Scopes that clients will use with user provided GoogleOAuth2 Service
 * Account Credentials.
 */
public class ContainerSecurityScopeRequirement extends GoogleOAuth2ScopeRequirement {

  /**
   * Returns the scopes that clients will need to use for this plugin.
   *
   * @return The set of required scopes.
   */
  @Override
  public Collection<String> getScopes() {
    return ImmutableSet.<String>builder()
        .addAll(BinaryAuthorizationScopes.all())
        .addAll(CloudKMSScopes.all())
        .addAll(ContainerAnalysisScopes.all())
        .addAll(CloudResourceManagerScopes.all())
        .build();
  }
}
