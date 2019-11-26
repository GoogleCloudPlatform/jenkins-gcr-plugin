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

import static com.google.jenkins.plugins.containersecurity.GcspBuild.CONTAINER_DIGEST_PATTERN;
import static com.google.jenkins.plugins.containersecurity.GcspBuild.CONTAINER_TAG_PATTERN;
import static com.google.jenkins.plugins.containersecurity.GcspBuild.CONTAINER_URI_PATTERN_TEMPLATE;
import static com.google.jenkins.plugins.containersecurity.util.TestUtil.assertFormValidationEquals;
import static com.google.jenkins.plugins.containersecurity.util.TestUtil.assertListBoxModelEquals;
import static com.google.jenkins.plugins.containersecurity.util.TestUtil.setUpProjectClientFactory;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;

import com.diffplug.common.base.Throwing.Specific;
import com.google.cloud.graphite.platforms.plugin.client.ClientFactory;
import com.google.common.collect.ImmutableList;
import com.google.jenkins.plugins.containersecurity.GcspBuild.DescriptorImpl;
import hudson.AbortException;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.ListBoxModel.Option;
import java.io.IOException;
import java.util.Optional;
import jenkins.model.Jenkins;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

/** Tests the {@link DescriptorImpl} for {@link GcspBuild}. */
@RunWith(MockitoJUnitRunner.class)
public class GcspBuildDescriptorTest {
  private static final String TEST_DIGEST =
      "sha256:0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff";

  @Mock public Jenkins jenkins;

  @Test
  public void testDoFillProjectIdItemsEmptyCredentialsId() {
    ListBoxModel expected = new ListBoxModel();
    expected.add(Messages.GcspBuild_ProjectCredentialIDRequired(), "");
    ListBoxModel actual = descriptor().doFillProjectIdItems(jenkins, "", "test");
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoFillProjectIdItemsInvalidCredentials() {
    String message =
        com.google.jenkins.plugins.containersecurity.client.Messages
            .ClientFactory_FailedToInitializeHTTPTransport("test");
    ListBoxModel expected = new ListBoxModel();
    expected.add(message, "");
    Specific.Supplier<ClientFactory, AbortException> supplier =
        () -> {
          throw new AbortException(message);
        };
    ListBoxModel actual = descriptor(supplier).doFillProjectIdItems(jenkins, "test", "test");
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoFillProjectIdItemsFillError() throws IOException {
    ClientFactory clientFactory =
        setUpProjectClientFactory(ImmutableList.of(), Optional.of(new IOException("test")));
    ListBoxModel expected = new ListBoxModel();
    expected.add(Messages.GcspBuild_ProjectIDFillError("test"), "");
    ListBoxModel actual =
        descriptor(() -> clientFactory).doFillProjectIdItems(jenkins, "test", "test");
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoFillProjectIdItemsEmptyProjectId() throws IOException {
    ClientFactory clientFactory =
        setUpProjectClientFactory(ImmutableList.of("test"), Optional.empty());

    ListBoxModel expected = new ListBoxModel().add("");
    expected.add(new Option("test", "test", true));
    ListBoxModel actual = descriptor(() -> clientFactory).doFillProjectIdItems(jenkins, "test", "");
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoFillProjectIdItems() throws IOException {
    ClientFactory clientFactory =
        setUpProjectClientFactory(ImmutableList.of("other", "test"), Optional.empty());

    ListBoxModel expected = new ListBoxModel().add("");
    expected.add(new Option("other", "other", true));
    expected.add("test");
    ListBoxModel actual =
        descriptor(() -> clientFactory).doFillProjectIdItems(jenkins, "test", "other");
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoCheckProjectIdEmptyCredentialsId() {
    FormValidation expected =
        FormValidation.error(Messages.GcspBuild_ProjectCredentialIDRequired());
    FormValidation actual = descriptor().doCheckProjectId(jenkins, "", "test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckProjectIdEmptyProjectId() {
    FormValidation expected = FormValidation.error(Messages.GcspBuild_ProjectIDRequired());
    FormValidation actual = descriptor().doCheckProjectId(jenkins, "test", "");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckProjectIdNoProjects() throws IOException {
    ClientFactory clientFactory = setUpProjectClientFactory(ImmutableList.of(), Optional.empty());

    FormValidation expected =
        FormValidation.error(Messages.GcspBuild_ProjectIDNotUnderCredential());
    FormValidation actual =
        descriptor(() -> clientFactory).doCheckProjectId(jenkins, "test", "test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckProjectIdNoMatchingProject() throws IOException {
    ClientFactory clientFactory =
        setUpProjectClientFactory(ImmutableList.of("other", "not-test"), Optional.empty());
    FormValidation expected =
        FormValidation.error(Messages.GcspBuild_ProjectIDNotUnderCredential());
    FormValidation actual =
        descriptor(() -> clientFactory).doCheckProjectId(jenkins, "test", "test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckProjectIdListProjectError() throws IOException {
    ClientFactory clientFactory =
        setUpProjectClientFactory(ImmutableList.of(), Optional.of(new IOException("test")));

    FormValidation expected =
        FormValidation.error(Messages.GcspBuild_ProjectIDVerificationError("test"));
    FormValidation actual =
        descriptor(() -> clientFactory).doCheckProjectId(jenkins, "test", "test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckProjectIdMatchingProject() throws IOException {
    ClientFactory clientFactory =
        setUpProjectClientFactory(ImmutableList.of("other", "test"), Optional.empty());

    FormValidation expected = FormValidation.ok();
    FormValidation actual =
        descriptor(() -> clientFactory).doCheckProjectId(jenkins, "test", "test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckContainerUriEmptyProjectId() {
    FormValidation expected =
        FormValidation.error(Messages.GcspBuild_ContainerURIProjectIdRequired());
    FormValidation actual = descriptor().doCheckContainerUri("", "gcr.io/test/test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckContainerUriEmptyContainerUri() {
    FormValidation expected = FormValidation.error(Messages.GcspBuild_ContainerURIRequired());
    FormValidation actual = descriptor().doCheckContainerUri("test", "");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckContainerUriNonMatching() {
    FormValidation expected =
        FormValidation.error(
            Messages.GcspBuild_ContainerPatternNoMatch(
                "URI", String.format(CONTAINER_URI_PATTERN_TEMPLATE, "test")));
    FormValidation actual = descriptor().doCheckContainerUri("test", "gcr.com/test/test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckContainerUriMatching() {
    FormValidation expected = FormValidation.ok();
    FormValidation actual = descriptor().doCheckContainerUri("test", "gcr.io/test/test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoFillContainerQualifierTypeItems() {
    ListBoxModel expected = new ListBoxModel();
    expected.add("Digest", "true");
    expected.add("Tag", "false");
    ListBoxModel actual = descriptor().doFillContainerQualifierTypeItems();
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoCheckContainerQualifierEmptyContainerQualifier() {
    FormValidation expected = FormValidation.error(Messages.GcspBuild_ContainerQualifierRequired());
    FormValidation actual = descriptor().doCheckContainerQualifier("test", "", true);
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckContainerQualifierDigestMacroPattern() {
    FormValidation expected =
        FormValidation.warning(Messages.GcspBuild_ContainerDigestMacroWarning());
    FormValidation actual = descriptor().doCheckContainerQualifier("test", "$TEST", true);
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckContainerQualifierDigestNoMatch() {
    FormValidation expected =
        FormValidation.error(
            Messages.GcspBuild_ContainerPatternNoMatch(
                "Digest", CONTAINER_DIGEST_PATTERN.toString()));
    // No match as a digest though this is a valid tag.
    FormValidation actual = descriptor().doCheckContainerQualifier("test", "test", true);
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckContainerQualifierDigestMatch() {
    FormValidation expected = FormValidation.ok();
    FormValidation actual = descriptor().doCheckContainerQualifier("test", TEST_DIGEST, true);
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckContainerQualifierTagInvalid() {
    FormValidation expected =
        FormValidation.error(
            Messages.GcspBuild_ContainerPatternNoMatch("Tag", CONTAINER_TAG_PATTERN.toString()));
    // No match as a tag, though it is a valid digest.
    FormValidation actual = descriptor().doCheckContainerQualifier("test", TEST_DIGEST, false);
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckContainerQualifierTagEmptyCredentialsId() {
    FormValidation expected =
        FormValidation.error(Messages.GcspBuild_ContainerTagCredentialIdRequired());
    FormValidation actual = descriptor().doCheckContainerQualifier("", "test", false);
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckContainerQualifierTagMatch() {
    FormValidation expected = FormValidation.ok();
    FormValidation actual = descriptor().doCheckContainerQualifier("test", "test", false);
    assertFormValidationEquals(expected, actual);
  }

  private static DescriptorImpl descriptor(
      Specific.Supplier<ClientFactory, AbortException> supplier) {
    DescriptorImpl descriptor = Mockito.spy(new DescriptorImpl());
    Mockito.doReturn(supplier).when(descriptor).clientFactory(any(), anyString());
    return descriptor;
  }

  public static DescriptorImpl descriptor() {
    return Mockito.spy(DescriptorImpl.class);
  }
}
