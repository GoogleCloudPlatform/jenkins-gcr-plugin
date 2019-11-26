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

package com.google.jenkins.plugins.containersecurity.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.ArgumentMatchers.any;

import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.services.cloudresourcemanager.model.Project;
import com.google.cloud.graphite.platforms.plugin.client.ClientFactory;
import com.google.cloud.graphite.platforms.plugin.client.CloudResourceManagerClient;
import com.google.common.collect.ImmutableList;
import com.google.jenkins.plugins.credentials.oauth.GoogleRobotCredentials;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.ListBoxModel.Option;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.mockito.BDDMockito;
import org.mockito.Mockito;

// TODO(stephenshank): Migrate to 'jenkins' module of gcp-plugin-core-java.
/** Utilities for common operations performed in multiple tests. */
public class TestUtil {
  // Required because equals not properly implemented for Option
  public static void assertOptionEquals(Option expected, Option actual) {
    if (expected == null) {
      assertNull(actual);
      return;
    }
    assertEquals(expected.name, actual.name);
    assertEquals(expected.value, actual.value);
    assertEquals(expected.selected, actual.selected);
  }

  // Required because equals not properly implemented for Option (the type of the elements).
  public static void assertListBoxModelEquals(ListBoxModel expected, ListBoxModel actual) {
    if (expected == null) {
      assertNull(actual);
      return;
    }
    assertEquals(expected.size(), actual.size());
    for (int i = 0; i < expected.size(); i++) {
      assertOptionEquals(expected.get(i), actual.get(i));
    }
  }

  // Required because equals not properly implemented for FormValidation.
  public static void assertFormValidationEquals(FormValidation expected, FormValidation actual) {
    if (expected == null) {
      assertNull(actual);
      return;
    }
    assertEquals(expected.kind, actual.kind);
    assertEquals(expected.getMessage(), actual.getMessage());
  }

  public static void clearCredentials() {
    SystemCredentialsProvider.getInstance().getCredentials().clear();
  }

  public static GoogleRobotCredentials addCredentials(String name)
      throws GeneralSecurityException, IOException {
    return addCredentials(name, Optional.empty());
  }

  public static GoogleRobotCredentials addCredentials(
      String name, Optional<GeneralSecurityException> gse)
      throws GeneralSecurityException, IOException {
    return addCredentials(name, gse, Optional.empty());
  }

  public static GoogleRobotCredentials addCredentials(
      String name, Optional<GeneralSecurityException> gse, Optional<IOException> ioe)
      throws GeneralSecurityException, IOException {
    GoogleRobotCredentials googleRobotCredentials = Mockito.mock(GoogleRobotCredentials.class);
    Mockito.when(googleRobotCredentials.getId()).thenReturn(name);
    // This is what is displayed as the "name" in GcspBuild.DescriptorImpl.doFillCredentialsIdItems.
    Mockito.when(googleRobotCredentials.getUsername()).thenReturn(name);
    if (gse.isPresent()) {
      Mockito.when(googleRobotCredentials.getGoogleCredential(any())).thenThrow(gse.get());
    } else {
      Credential credential = Mockito.mock(Credential.class);
      // BDDMockito.given because refreshToken is final
      if (ioe.isPresent()) {
        BDDMockito.given(credential.refreshToken()).willThrow(ioe.get());
      } else {
        BDDMockito.given(credential.refreshToken()).willReturn(true);
      }
      Mockito.when(googleRobotCredentials.getGoogleCredential(any())).thenReturn(credential);
    }
    SystemCredentialsProvider.getInstance().getCredentials().add(googleRobotCredentials);
    return googleRobotCredentials;
  }

  public static <T> ImmutableList<T> setUpItemList(List<String> ids, Function<String, T> mapping) {
    return ImmutableList.copyOf(ids.stream().map(mapping).collect(Collectors.toList()));
  }

  public static ImmutableList<Project> setUpProjectList(List<String> projectIds) {
    return setUpItemList(projectIds, p -> new Project().setProjectId(p));
  }

  public static ClientFactory setUpProjectClientFactory(
      List<String> projects, Optional<IOException> ioe) throws IOException {
    ClientFactory clientFactory = Mockito.mock(ClientFactory.class);
    CloudResourceManagerClient cloudResourceManagerClient =
        Mockito.mock(CloudResourceManagerClient.class);
    if (ioe.isPresent()) {
      Mockito.when(cloudResourceManagerClient.listProjects()).thenThrow(ioe.get());
    } else {
      Mockito.when(cloudResourceManagerClient.listProjects())
          .thenReturn(setUpProjectList(projects));
    }
    Mockito.when(clientFactory.cloudResourceManagerClient()).thenReturn(cloudResourceManagerClient);
    return clientFactory;
  }
}
