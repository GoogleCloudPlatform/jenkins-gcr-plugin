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

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.http.HttpTransport;
import com.google.cloud.graphite.platforms.plugin.client.ClientFactory;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.jenkins.plugins.credentials.oauth.GoogleOAuth2Credentials;
import com.google.jenkins.plugins.credentials.oauth.GoogleRobotCredentials;
import hudson.AbortException;
import hudson.model.ItemGroup;
import hudson.security.ACL;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Optional;
import lombok.NonNull;

/**
 * Common utility methods for generating a {@link ClientFactory} that can be used to generate
 * clients.
 */
public class ClientUtil {
  private static final String APPLICATION_NAME = "jenkins-google-container-security";

  /**
   * Creates a {@link ClientFactory} for generating the GCP API clients.
   *
   * @param itemGroup The Jenkins context to use for retrieving the credentials.
   * @param domainRequirements A list of domain requirements.
   * @param credentialsId The ID of the credentials to use for generating clients.
   * @param transport An {@link Optional} parameter that specifies the {@link HttpTransport} to use.
   *     A default will be used if unspecified.
   * @return A {@link ClientFactory} to get clients.
   * @throws AbortException If there was an error initializing the ClientFactory.
   */
  public static ClientFactory getClientFactory(
      @NonNull ItemGroup itemGroup,
      @NonNull ImmutableList<DomainRequirement> domainRequirements,
      @NonNull String credentialsId,
      @NonNull Optional<HttpTransport> transport)
      throws AbortException {
    Preconditions.checkArgument(
        !credentialsId.isEmpty(), Messages.ClientFactory_CredentialsIdRequired());

    ClientFactory clientFactory;
    try {
      GoogleRobotCredentials robotCreds =
          getRobotCredentials(itemGroup, domainRequirements, credentialsId);
      Credential googleCredential = getGoogleCredential(robotCreds);
      clientFactory = new ClientFactory(transport, googleCredential, APPLICATION_NAME);
    } catch (IOException | GeneralSecurityException ex) {
      throw new AbortException(Messages.ClientFactory_FailedToInitializeHTTPTransport(ex));
    }
    return clientFactory;
  }

  /**
   * Creates a {@link ClientFactory} for generating the GCP API clients.
   *
   * @param itemGroup The Jenkins context to use for retrieving the credentials.
   * @param credentialsId The ID of the credentials to use for generating clients.
   * @return A {@link ClientFactory} to get clients.
   * @throws AbortException If there was an error initializing the ClientFactory.
   */
  public static ClientFactory getClientFactory(ItemGroup itemGroup, String credentialsId)
      throws AbortException {
    return getClientFactory(itemGroup, ImmutableList.of(), credentialsId, Optional.empty());
  }

  /**
   * Retrieves the {@link GoogleRobotCredentials} specified by the provided credentialsId.
   *
   * @param itemGroup The Jenkins context to use for retrieving the credentials.
   * @param domainRequirements A list of domain requirements.
   * @param credentialsId The ID of the credentials to retrieve.
   * @return The {@link GoogleRobotCredentials} with the provided ID.
   * @throws AbortException If there was an error retrieving the credentials.
   */
  public static GoogleRobotCredentials getRobotCredentials(
      @NonNull ItemGroup itemGroup,
      @NonNull List<DomainRequirement> domainRequirements,
      @NonNull String credentialsId)
      throws AbortException {
    Preconditions.checkArgument(!credentialsId.isEmpty());
    GoogleOAuth2Credentials credentials =
        CredentialsMatchers.firstOrNull(
            CredentialsProvider.lookupCredentials(
                GoogleOAuth2Credentials.class, itemGroup, ACL.SYSTEM, domainRequirements),
            CredentialsMatchers.withId(credentialsId));

    if (!(credentials instanceof GoogleRobotCredentials)) {
      throw new AbortException(Messages.ClientFactory_FailedToRetrieveCredentials(credentialsId));
    }

    return (GoogleRobotCredentials) credentials;
  }

  private static Credential getGoogleCredential(GoogleRobotCredentials credentials)
      throws GeneralSecurityException {
    return credentials.getGoogleCredential(new ContainerSecurityScopeRequirement());
  }
}
