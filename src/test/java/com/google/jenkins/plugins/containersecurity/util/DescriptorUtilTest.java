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

import static com.google.jenkins.plugins.containersecurity.client.ClientUtil.getClientFactory;
import static com.google.jenkins.plugins.containersecurity.util.DescriptorUtil.checkPermissions;
import static com.google.jenkins.plugins.containersecurity.util.DescriptorUtil.selectOption;
import static com.google.jenkins.plugins.containersecurity.util.DescriptorUtil.validateRequiredFields;
import static com.google.jenkins.plugins.containersecurity.util.DescriptorUtil.validateWithClientFactory;
import static com.google.jenkins.plugins.containersecurity.util.TestUtil.addCredentials;
import static com.google.jenkins.plugins.containersecurity.util.TestUtil.assertFormValidationEquals;
import static com.google.jenkins.plugins.containersecurity.util.TestUtil.assertListBoxModelEquals;
import static com.google.jenkins.plugins.containersecurity.util.TestUtil.assertOptionEquals;
import static com.google.jenkins.plugins.containersecurity.util.TestUtil.clearCredentials;

import com.google.cloud.graphite.platforms.plugin.client.ClientFactory;
import com.google.common.collect.ImmutableList;
import com.google.jenkins.plugins.containersecurity.client.Messages;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.ListBoxModel.Option;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Optional;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.WithoutJenkins;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

/** Tests {@link DescriptorUtil}. */
@RunWith(MockitoJUnitRunner.class)
public class DescriptorUtilTest {
  @Rule public JenkinsRule jenkinsRule = new JenkinsRule();

  @Test
  public void testCheckPermissions() {
    checkPermissions();
  }

  @WithoutJenkins
  @Test
  public void testSelectOptionNullListBoxModel() {
    selectOption(null, "test");
  }

  @WithoutJenkins
  @Test
  public void testSelectOptionEmptyListBoxModel() {
    // Verifies that this silently continues
    selectOption(new ListBoxModel(), "test");
  }

  @WithoutJenkins
  @Test
  public void testSelectOptionNullOptionValue() {
    ListBoxModel listBoxModel = new ListBoxModel().add("test");
    selectOption(listBoxModel, null);
    Option expected = new Option("test", "test", true);
    assertOptionEquals(expected, listBoxModel.get(0));
  }

  @WithoutJenkins
  @Test
  public void testSelectOptionEmptyOptionValue() {
    ListBoxModel listBoxModel = new ListBoxModel().add("test");
    selectOption(listBoxModel, "");
    Option expected = new Option("test", "test", true);
    assertOptionEquals(listBoxModel.get(0), expected);
  }

  @WithoutJenkins
  @Test
  public void testSelectOptionNonexistentValue() {
    ListBoxModel listBoxModel = new ListBoxModel().add("test");
    selectOption(listBoxModel, "other");
    Option expected = new Option("test", "test", true);
    assertOptionEquals(listBoxModel.get(0), expected);
  }

  @WithoutJenkins
  @Test
  public void testSelectOption() {
    ListBoxModel listBoxModel = new ListBoxModel().add("test").add("other").add("example");
    selectOption(listBoxModel, "other");
    ListBoxModel expected = new ListBoxModel().add("test").add("other").add("example");
    expected.get(1).selected = true;
    assertListBoxModelEquals(expected, listBoxModel);
  }

  @WithoutJenkins
  @Test(expected = NullPointerException.class)
  public void testValidateRequiredFieldsNullFields() {
    validateRequiredFields(null, ImmutableList.of(), FormValidation::ok);
  }

  @WithoutJenkins
  @Test(expected = NullPointerException.class)
  public void testValidateRequiredFieldsNullMessages() {
    validateRequiredFields(ImmutableList.of(), null, FormValidation::ok);
  }

  @WithoutJenkins
  @Test(expected = NullPointerException.class)
  public void testValidateRequiredFieldsNullCallback() {
    validateRequiredFields(ImmutableList.of(), ImmutableList.of(), null);
  }

  @WithoutJenkins
  @Test(expected = IllegalStateException.class)
  public void testValidateRequiredFieldsUnevenLists() {
    validateRequiredFields(ImmutableList.of(), ImmutableList.of("test"), FormValidation::ok);
  }

  @WithoutJenkins
  @Test
  public void testValidateRequiredFieldsEmptyFields() {
    FormValidation expected = FormValidation.error("test");
    FormValidation actual =
        validateRequiredFields(ImmutableList.of(""), ImmutableList.of("test"), FormValidation::ok);
    assertFormValidationEquals(expected, actual);
  }

  @WithoutJenkins
  @Test
  public void testValidateRequiredFieldsMultipleWithOneEmpty() {
    FormValidation expected = FormValidation.error("second");
    FormValidation actual =
        validateRequiredFields(
            // Tests that order is preserved and the earliest empty field results in an error.
            ImmutableList.of("test", "", "test", ""),
            ImmutableList.of("first", "second", "third", "fourth"),
            FormValidation::ok);
    assertFormValidationEquals(expected, actual);
  }

  @WithoutJenkins
  @Test
  public void testValidateRequiredFieldsNoEmptyFields() {
    FormValidation expected = FormValidation.error("other");
    FormValidation actual =
        validateRequiredFields(ImmutableList.of("test"), ImmutableList.of("test"), () -> expected);
    assertFormValidationEquals(expected, actual);
  }

  @WithoutJenkins
  @Test(expected = NullPointerException.class)
  public void testValidateWithClientFactoryNullClientFactorySupplier() {
    validateWithClientFactory(null, c -> FormValidation.ok());
  }

  @WithoutJenkins
  @Test(expected = NullPointerException.class)
  public void testValidateWithClientFactoryNullCallback() {
    ClientFactory clientFactory = Mockito.mock(ClientFactory.class);
    validateWithClientFactory(() -> clientFactory, null);
  }

  @Test
  public void testValidateWithClientFactoryNoCredentials() {
    clearCredentials();
    FormValidation expected =
        FormValidation.error(
            Messages.ClientFactory_FailedToInitializeHTTPTransport(
                "hudson.AbortException: "
                    + Messages.ClientFactory_FailedToRetrieveCredentials("test")));
    FormValidation actual =
        validateWithClientFactory(
            () -> getClientFactory(jenkinsRule.jenkins, "test"), c -> FormValidation.ok());
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testValidateWithClientFactoryInvalidCredentials()
      throws GeneralSecurityException, IOException {
    clearCredentials();
    addCredentials("test", Optional.of(new GeneralSecurityException("test")));

    FormValidation expected =
        FormValidation.error(
            Messages.ClientFactory_FailedToInitializeHTTPTransport(
                "java.security.GeneralSecurityException: test"));
    FormValidation actual =
        validateWithClientFactory(
            () -> getClientFactory(jenkinsRule.jenkins, "test"), cf -> FormValidation.ok());
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testValidateWithClientFactoryValidCredentials()
      throws GeneralSecurityException, IOException {
    clearCredentials();
    addCredentials("test");

    FormValidation expected = FormValidation.error("Working as intended");
    FormValidation actual =
        validateWithClientFactory(
            () -> getClientFactory(jenkinsRule.jenkins, "test"), cf -> expected);
    assertFormValidationEquals(expected, actual);
  }
}
