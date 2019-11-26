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

package com.google.jenkins.plugins.containersecurity;

import static com.google.jenkins.plugins.containersecurity.GcspBuildDescriptorTest.descriptor;
import static com.google.jenkins.plugins.containersecurity.util.TestUtil.addCredentials;
import static com.google.jenkins.plugins.containersecurity.util.TestUtil.assertFormValidationEquals;
import static com.google.jenkins.plugins.containersecurity.util.TestUtil.assertListBoxModelEquals;
import static com.google.jenkins.plugins.containersecurity.util.TestUtil.clearCredentials;

import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Optional;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.WithoutJenkins;
import org.mockito.junit.MockitoJUnitRunner;

/**
 * Tests the {@link DescriptorImpl} for {@link GcspBuild}, specifically dealing with the credentials
 * ID selector.
 */
@RunWith(MockitoJUnitRunner.class)
public class GcspBuildCredentialDescriptorTest {
  @Rule public JenkinsRule jenkinsRule = new JenkinsRule();

  @Test
  public void testDoFillCredentialsIdItemsNoCredentials() {
    ListBoxModel expected = new StandardListBoxModel().includeEmptyValue();
    ListBoxModel actual = descriptor().doFillCredentialsIdItems(jenkinsRule.jenkins);
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoFillCredentialsIdItemsWithCredentials()
      throws GeneralSecurityException, IOException {
    addCredentials("test");
    ListBoxModel expected = new StandardListBoxModel().includeEmptyValue().add("test");
    ListBoxModel actual = descriptor().doFillCredentialsIdItems(jenkinsRule.jenkins);
    assertListBoxModelEquals(expected, actual);
  }

  @WithoutJenkins
  @Test
  public void testDoCheckCredentialsIdEmptyCredentialsId() {
    FormValidation expected = FormValidation.error(Messages.GcspBuild_NoCredential());
    FormValidation actual = descriptor().doCheckCredentialsId(jenkinsRule.jenkins, "");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckCredentialsIdNoCredentials() {
    clearCredentials();
    FormValidation expected =
        FormValidation.error(
            com.google.jenkins.plugins.containersecurity.client.Messages
                .ClientFactory_FailedToRetrieveCredentials("test"));
    FormValidation actual = descriptor().doCheckCredentialsId(jenkinsRule.jenkins, "test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckCredentialsIdInvalidCredentials()
      throws GeneralSecurityException, IOException {
    clearCredentials();
    addCredentials("test", Optional.of(new GeneralSecurityException("test")));

    FormValidation expected = FormValidation.error(Messages.GcspBuild_CredentialAuthFailed());
    FormValidation actual = descriptor().doCheckCredentialsId(jenkinsRule.jenkins, "test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckCredentialsIdValidCredentialsFailedRefresh()
      throws GeneralSecurityException, IOException {
    clearCredentials();
    addCredentials("test", Optional.empty(), Optional.of(new IOException("test")));
    FormValidation expected = FormValidation.error(Messages.GcspBuild_CredentialAuthFailed());
    FormValidation actual = descriptor().doCheckCredentialsId(jenkinsRule.jenkins, "test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckCredentialsIdValidCredentials()
      throws GeneralSecurityException, IOException {
    clearCredentials();
    addCredentials("test");
    FormValidation expected = FormValidation.ok();
    FormValidation actual = descriptor().doCheckCredentialsId(jenkinsRule.jenkins, "test");
    assertFormValidationEquals(expected, actual);
  }
}
