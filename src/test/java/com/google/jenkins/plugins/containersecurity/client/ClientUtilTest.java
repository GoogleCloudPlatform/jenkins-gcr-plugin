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

import static com.google.jenkins.plugins.containersecurity.client.ClientUtil.getClientFactory;
import static com.google.jenkins.plugins.containersecurity.client.ClientUtil.getRobotCredentials;
import static com.google.jenkins.plugins.containersecurity.util.TestUtil.addCredentials;
import static com.google.jenkins.plugins.containersecurity.util.TestUtil.clearCredentials;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.mock;

import com.google.cloud.graphite.platforms.plugin.client.ClientFactory;
import com.google.common.collect.ImmutableList;
import com.google.jenkins.plugins.credentials.oauth.GoogleRobotCredentials;
import hudson.AbortException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Optional;
import jenkins.model.Jenkins;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.WithoutJenkins;
import org.mockito.junit.MockitoJUnitRunner;

/** Tests {@link ClientUtil}. */
@RunWith(MockitoJUnitRunner.class)
public class ClientUtilTest {
  @Rule public JenkinsRule jenkinsRule = new JenkinsRule();

  @WithoutJenkins
  @Test(expected = NullPointerException.class)
  public void testGetClientFactoryNullItemGroup() throws AbortException {
    getClientFactory(null, ImmutableList.of(), "test", Optional.empty());
  }

  @WithoutJenkins
  @Test(expected = NullPointerException.class)
  public void testGetClientFactoryNullDomainRequirements() throws AbortException {
    getClientFactory(mock(Jenkins.class), null, "test", Optional.empty());
  }

  @WithoutJenkins
  @Test(expected = NullPointerException.class)
  public void testGetClientFactoryNullCredentialsId() throws AbortException {
    getClientFactory(mock(Jenkins.class), ImmutableList.of(), null, Optional.empty());
  }

  @WithoutJenkins
  @Test(expected = IllegalArgumentException.class)
  public void testGetClientFactoryEmptyCredentialsId() throws AbortException {
    getClientFactory(mock(Jenkins.class), ImmutableList.of(), "", Optional.empty());
  }

  @WithoutJenkins
  @Test(expected = NullPointerException.class)
  public void testGetClientFactoryNullTransport() throws AbortException {
    getClientFactory(mock(Jenkins.class), ImmutableList.of(), "test", null);
  }

  @Test(expected = AbortException.class)
  public void testGetClientFactoryNoCredentials() throws AbortException {
    clearCredentials();
    try {
      getClientFactory(jenkinsRule.jenkins, "test");
    } catch (AbortException e) {
      assertEquals(
          Messages.ClientFactory_FailedToInitializeHTTPTransport(
              "hudson.AbortException: "
                  + Messages.ClientFactory_FailedToRetrieveCredentials("test")),
          e.getMessage());
      throw e;
    }
  }

  @Test(expected = AbortException.class)
  public void testGetClientFactoryInvalidCredentials()
      throws GeneralSecurityException, IOException {
    clearCredentials();
    addCredentials("test", Optional.of(new GeneralSecurityException("test")));

    try {
      getClientFactory(jenkinsRule.jenkins, "test");
    } catch (AbortException e) {
      assertEquals(
          Messages.ClientFactory_FailedToInitializeHTTPTransport(
              "java.security.GeneralSecurityException: test"),
          e.getMessage());
      throw e;
    }
  }

  @Test
  public void testGetClientFactoryValidCredentials() throws GeneralSecurityException, IOException {
    clearCredentials();
    addCredentials("test");

    ClientFactory result = getClientFactory(jenkinsRule.jenkins, "test");
    assertNotNull(result);
  }

  @WithoutJenkins
  @Test(expected = NullPointerException.class)
  public void testGetRobotCredentialsNullItemGroup() throws AbortException {
    getRobotCredentials(null, ImmutableList.of(), "test");
  }

  @WithoutJenkins
  @Test(expected = NullPointerException.class)
  public void testGetRobotCredentialsNullDomainRequirements() throws AbortException {
    getRobotCredentials(mock(Jenkins.class), null, "test");
  }

  @WithoutJenkins
  @Test(expected = NullPointerException.class)
  public void testGetRobotCredentialsNullCredentialsId() throws AbortException {
    getRobotCredentials(mock(Jenkins.class), ImmutableList.of(), null);
  }

  @WithoutJenkins
  @Test(expected = IllegalArgumentException.class)
  public void testGetRobotCredentialsEmptyCredentialsId() throws AbortException {
    getRobotCredentials(mock(Jenkins.class), ImmutableList.of(), "");
  }

  @Test(expected = AbortException.class)
  public void testGetRobotCredentialsNoCredentials() throws AbortException {
    clearCredentials();
    try {
      getRobotCredentials(jenkinsRule.jenkins, ImmutableList.of(), "test");
    } catch (AbortException e) {
      assertEquals(Messages.ClientFactory_FailedToRetrieveCredentials("test"), e.getMessage());
      throw e;
    }
  }

  @Test
  public void testGetRobotCredentialsWithCredentials()
      throws GeneralSecurityException, IOException {
    clearCredentials();
    GoogleRobotCredentials expected = addCredentials("test", Optional.empty());

    GoogleRobotCredentials actual =
        getRobotCredentials(jenkinsRule.jenkins, ImmutableList.of(), "test");
    assertEquals(expected, actual);
  }
}
