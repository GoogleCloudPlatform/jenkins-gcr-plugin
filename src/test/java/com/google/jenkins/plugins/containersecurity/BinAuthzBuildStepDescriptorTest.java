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

import static com.google.jenkins.plugins.containersecurity.util.TestUtil.assertFormValidationEquals;
import static com.google.jenkins.plugins.containersecurity.util.TestUtil.assertListBoxModelEquals;
import static com.google.jenkins.plugins.containersecurity.util.TestUtil.setUpItemList;
import static com.google.jenkins.plugins.containersecurity.util.TestUtil.setUpProjectClientFactory;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;

import com.diffplug.common.base.Throwing.Specific;
import com.diffplug.common.base.Throwing.Specific.Supplier;
import com.google.api.services.binaryauthorization.v1beta1.model.Attestor;
import com.google.api.services.binaryauthorization.v1beta1.model.AttestorPublicKey;
import com.google.api.services.binaryauthorization.v1beta1.model.UserOwnedDrydockNote;
import com.google.cloud.graphite.platforms.plugin.client.BinaryAuthorizationClient;
import com.google.cloud.graphite.platforms.plugin.client.ClientFactory;
import com.google.common.collect.ImmutableList;
import com.google.jenkins.plugins.containersecurity.BinAuthzBuildStep.DescriptorImpl;
import hudson.AbortException;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.ListBoxModel.Option;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import jenkins.model.Jenkins;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

/** Tests the {@link DescriptorImpl} of {@link BinAuthzBuildStep}. */
@RunWith(MockitoJUnitRunner.class)
public class BinAuthzBuildStepDescriptorTest {
  @Mock Jenkins jenkins;

  @Test
  public void testDoFillAttestorProjectIdItemsEmptyCredentialsId() {
    ListBoxModel expected = new ListBoxModel();
    expected.add(Messages.GcspBuild_ProjectCredentialIDRequired(), "");
    ListBoxModel actual = descriptor().doFillAttestorProjectIdItems(jenkins, "", "test");
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoFillAttestorProjectIdItemsInvalidCredentials() {
    String message =
        com.google.jenkins.plugins.containersecurity.client.Messages
            .ClientFactory_FailedToInitializeHTTPTransport("test");
    ListBoxModel expected = new ListBoxModel();
    expected.add(message, "");
    Specific.Supplier<ClientFactory, AbortException> supplier =
        () -> {
          throw new AbortException(message);
        };
    ListBoxModel actual =
        descriptor(supplier).doFillAttestorProjectIdItems(jenkins, "test", "test");
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoFillAttestorProjectIdItemsFillError() throws IOException {
    ClientFactory clientFactory =
        setUpProjectClientFactory(ImmutableList.of(), Optional.of(new IOException("test")));
    ListBoxModel expected = new ListBoxModel();
    expected.add(Messages.GcspBuild_ProjectIDFillError("test"), "");
    ListBoxModel actual =
        descriptor(() -> clientFactory).doFillAttestorProjectIdItems(jenkins, "test", "test");
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoFillAttestorProjectIdItemsEmptyAttestorProjectId() throws IOException {
    ClientFactory clientFactory =
        setUpProjectClientFactory(ImmutableList.of("test"), Optional.empty());

    ListBoxModel expected = new ListBoxModel().add("");
    expected.add(new Option("test", "test", true));
    ListBoxModel actual =
        descriptor(() -> clientFactory).doFillAttestorProjectIdItems(jenkins, "test", "");
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoFillAttestorProjectIdItems() throws IOException {
    ClientFactory clientFactory =
        setUpProjectClientFactory(ImmutableList.of("other", "test"), Optional.empty());

    ListBoxModel expected = new ListBoxModel().add("");
    expected.add(new Option("other", "other", true));
    expected.add("test");
    ListBoxModel actual =
        descriptor(() -> clientFactory).doFillAttestorProjectIdItems(jenkins, "test", "other");
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoCheckAttestorProjectIdEmptyCredentialsId() {
    FormValidation expected =
        FormValidation.error(Messages.GcspBuild_ProjectCredentialIDRequired());
    FormValidation actual = descriptor().doCheckAttestorProjectId(jenkins, "", "test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckAttestorProjectIdEmptyAttestorProjectId() {
    FormValidation expected =
        FormValidation.error(Messages.BinAuthzBuildStep_AttestorProjectIDRequired());
    FormValidation actual = descriptor().doCheckAttestorProjectId(jenkins, "test", "");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckAttestorProjectIdNoProjects() throws IOException {
    ClientFactory clientFactory = setUpProjectClientFactory(ImmutableList.of(), Optional.empty());

    FormValidation expected =
        FormValidation.error(Messages.GcspBuild_ProjectIDNotUnderCredential());
    FormValidation actual =
        descriptor(() -> clientFactory).doCheckAttestorProjectId(jenkins, "test", "test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckAttestorProjectIdNoMatchingProject() throws IOException {
    ClientFactory clientFactory =
        setUpProjectClientFactory(ImmutableList.of("other", "not-test"), Optional.empty());
    FormValidation expected =
        FormValidation.error(Messages.GcspBuild_ProjectIDNotUnderCredential());
    FormValidation actual =
        descriptor(() -> clientFactory).doCheckAttestorProjectId(jenkins, "test", "test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckAttestorProjectIdListProjectError() throws IOException {
    ClientFactory clientFactory =
        setUpProjectClientFactory(ImmutableList.of(), Optional.of(new IOException("test")));

    FormValidation expected =
        FormValidation.error(Messages.GcspBuild_ProjectIDVerificationError("test"));
    FormValidation actual =
        descriptor(() -> clientFactory).doCheckAttestorProjectId(jenkins, "test", "test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckAttestorProjectIdMatchingProject() throws IOException {
    ClientFactory clientFactory =
        setUpProjectClientFactory(ImmutableList.of("other", "test"), Optional.empty());

    FormValidation expected = FormValidation.ok();
    FormValidation actual =
        descriptor(() -> clientFactory).doCheckAttestorProjectId(jenkins, "test", "test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoFillAttestorIdItemsEmptyCredentialsId() {
    ListBoxModel expected = new ListBoxModel();
    expected.add(Messages.GcspBuild_ProjectCredentialIDRequired(), "");
    ListBoxModel actual = descriptor().doFillAttestorIdItems(jenkins, "", "test", "test");
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoFillAttestorIdItemsEmptyAttestorProjectId() {
    ListBoxModel expected = new ListBoxModel();
    expected.add(Messages.BinAuthzBuildStep_AttestorIDProjectIDRequired(), "");
    ListBoxModel actual = descriptor().doFillAttestorIdItems(jenkins, "test", "", "test");
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoFillAttestorIdItemsInvalidClientFactory() {
    Supplier<ClientFactory, AbortException> supplier =
        () -> {
          throw new AbortException("test");
        };
    ListBoxModel expected = new ListBoxModel();
    expected.add("test", "");
    ListBoxModel actual =
        descriptor(supplier).doFillAttestorIdItems(jenkins, "test", "test", "test");
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoFillAttestorIdItemsFillError() throws IOException {
    ClientFactory clientFactory =
        setupListAttestorClientFactory(ImmutableList.of(), Optional.of(new IOException("test")));
    ListBoxModel expected = new ListBoxModel();
    expected.add(Messages.BinAuthzBuildStep_AttestorIDFillError("test"), "");
    ListBoxModel actual =
        descriptor(() -> clientFactory).doFillAttestorIdItems(jenkins, "test", "test", "test");
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoFillAttestorIdItemsNoAttestors() throws IOException {
    ClientFactory clientFactory =
        setupListAttestorClientFactory(ImmutableList.of(), Optional.empty());
    ListBoxModel expected = new ListBoxModel().add("");
    ListBoxModel actual =
        descriptor(() -> clientFactory).doFillAttestorIdItems(jenkins, "test", "test", "test");
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoFillAttestorIdItemsEmptyAttestorId() throws IOException {
    ClientFactory clientFactory =
        setupListAttestorClientFactory(ImmutableList.of("other", "test"), Optional.empty());
    ListBoxModel expected = new ListBoxModel().add("").add("other").add("test");
    expected.get(1).selected = true;
    ListBoxModel actual =
        descriptor(() -> clientFactory).doFillAttestorIdItems(jenkins, "test", "test", "");
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoFillAttestorIdItems() throws IOException {
    ClientFactory clientFactory =
        setupListAttestorClientFactory(ImmutableList.of("other", "test"), Optional.empty());
    ListBoxModel expected = new ListBoxModel().add("").add("other").add("test");
    expected.get(2).selected = true;
    ListBoxModel actual =
        descriptor(() -> clientFactory).doFillAttestorIdItems(jenkins, "test", "test", "test");
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoCheckAttestorIdEmptyCredentialsId() {
    FormValidation expected =
        FormValidation.error(Messages.GcspBuild_ProjectCredentialIDRequired());
    FormValidation actual = descriptor().doCheckAttestorId(jenkins, "", "test", "test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckAttestorIdEmptyAttestorProjectId() {
    FormValidation expected =
        FormValidation.error(Messages.BinAuthzBuildStep_AttestorIDProjectIDRequired());
    FormValidation actual = descriptor().doCheckAttestorId(jenkins, "test", "", "test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckAttestorIdEmptyAttestorId() {
    FormValidation expected = FormValidation.error(Messages.BinAuthzBuildStep_AttestorIDRequired());
    FormValidation actual = descriptor().doCheckAttestorId(jenkins, "test", "test", "");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckAttestorIdInvalidClientFactory() {
    Supplier<ClientFactory, AbortException> supplier =
        () -> {
          throw new AbortException("test");
        };
    FormValidation expected = FormValidation.error("test");
    FormValidation actual = descriptor(supplier).doCheckAttestorId(jenkins, "test", "test", "test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckAttestorIdVerificationError() throws IOException {
    ClientFactory clientFactory =
        setupListAttestorClientFactory(ImmutableList.of(), Optional.of(new IOException("test")));
    FormValidation expected =
        FormValidation.error(Messages.BinAuthzBuildStep_AttestorIDVerificationError("test"));
    FormValidation actual =
        descriptor(() -> clientFactory).doCheckAttestorId(jenkins, "test", "test", "test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckAttestorIdNoAttestors() throws IOException {
    ClientFactory clientFactory =
        setupListAttestorClientFactory(ImmutableList.of(), Optional.empty());
    FormValidation expected =
        FormValidation.error(Messages.BinAuthzBuildStep_AttestorIDNotUnderProject());
    FormValidation actual =
        descriptor(() -> clientFactory).doCheckAttestorId(jenkins, "test", "test", "test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckAttestorId() throws IOException {
    ClientFactory clientFactory =
        setupListAttestorClientFactory(ImmutableList.of("other", "test"), Optional.empty());
    FormValidation expected = FormValidation.ok();
    FormValidation actual =
        descriptor(() -> clientFactory).doCheckAttestorId(jenkins, "test", "test", "test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoFillPublicKeyIdItemsEmptyCredentialsId() {
    ListBoxModel expected = new ListBoxModel();
    expected.add(Messages.GcspBuild_ProjectCredentialIDRequired(), "");
    ListBoxModel actual = descriptor().doFillPublicKeyIdItems(jenkins, "", "test", "test", "test");
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoFillPublicKeyIdItemsEmptyAttestorProjectId() {
    ListBoxModel expected = new ListBoxModel();
    expected.add(Messages.BinAuthzBuildStep_PublicKeyIDProjectIdRequired(), "");

    ListBoxModel actual = descriptor().doFillPublicKeyIdItems(jenkins, "test", "", "test", "test");
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoFillPublicKeyIdItemsEmptyAttestorId() {
    ListBoxModel expected = new ListBoxModel();
    expected.add(Messages.BinAuthzBuildStep_PublicKeyIDAttestorIDRequired(), "");
    ListBoxModel actual = descriptor().doFillPublicKeyIdItems(jenkins, "test", "test", "", "test");
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoFillPublicKeyIdItemsInvalidClientFactory() {
    Supplier<ClientFactory, AbortException> supplier =
        () -> {
          throw new AbortException("test");
        };
    ListBoxModel expected = new ListBoxModel();
    expected.add("test", "");
    ListBoxModel actual =
        descriptor(supplier).doFillPublicKeyIdItems(jenkins, "test", "test", "test", "test");
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoFillPublicKeyIdItemsFillError() throws IOException {
    ClientFactory clientFactory =
        setupListPublicKeysClientFactory(ImmutableList.of(), Optional.of(new IOException("test")));
    ListBoxModel expected = new ListBoxModel();
    expected.add(Messages.BinAuthzBuildStep_PublicKeyIDFillError("test"));
    ListBoxModel actual =
        descriptor(() -> clientFactory)
            .doFillPublicKeyIdItems(jenkins, "test", "test", "test", "test");
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoFillPublicKeyIdItemsNoPublicKeys() throws IOException {
    ClientFactory clientFactory =
        setupListPublicKeysClientFactory(ImmutableList.of(), Optional.empty());
    ListBoxModel expected = new ListBoxModel().add("");
    ListBoxModel actual =
        descriptor(() -> clientFactory)
            .doFillPublicKeyIdItems(jenkins, "test", "test", "test", "test");
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoFillPublicKeyIdItemsEmptyPublicKeyId() throws IOException {
    ClientFactory clientFactory =
        setupListPublicKeysClientFactory(ImmutableList.of("other", "test"), Optional.empty());
    ListBoxModel expected =
        new ListBoxModel().add("").add(publicKeyId("other")).add(publicKeyId("test"));
    expected.get(1).selected = true;
    ListBoxModel actual =
        descriptor(() -> clientFactory).doFillPublicKeyIdItems(jenkins, "test", "test", "test", "");
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoFillPublicKeyIdItems() throws IOException {
    ClientFactory clientFactory =
        setupListPublicKeysClientFactory(ImmutableList.of("other", "test"), Optional.empty());
    ListBoxModel expected =
        new ListBoxModel().add("").add(publicKeyId("other")).add(publicKeyId("test"));
    expected.get(2).selected = true;
    ListBoxModel actual =
        descriptor(() -> clientFactory)
            .doFillPublicKeyIdItems(jenkins, "test", "test", "test", publicKeyId("test"));
    assertListBoxModelEquals(expected, actual);
  }

  @Test
  public void testDoCheckPublicKeyIdEmptyCredentialsId() {
    FormValidation expected =
        FormValidation.error(Messages.GcspBuild_ProjectCredentialIDRequired());
    FormValidation actual = descriptor().doCheckPublicKeyId(jenkins, "", "test", "test", "test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckPublicKeyIdEmptyAttestorProjectId() {
    FormValidation expected =
        FormValidation.error(Messages.BinAuthzBuildStep_PublicKeyIDProjectIdRequired());
    FormValidation actual = descriptor().doCheckPublicKeyId(jenkins, "test", "", "test", "test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckPublicKeyIdEmptyAttestorId() {
    FormValidation expected =
        FormValidation.error(Messages.BinAuthzBuildStep_PublicKeyIDAttestorIDRequired());
    FormValidation actual = descriptor().doCheckPublicKeyId(jenkins, "test", "test", "", "test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckPublicKeyIdEmptyPublicKeyId() {
    FormValidation expected =
        FormValidation.error(Messages.BinAuthzBuildStep_PublicKeyIDRequired());
    FormValidation actual = descriptor().doCheckPublicKeyId(jenkins, "test", "test", "test", "");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckPublicKeyIdInvalidClientFactory() {
    Supplier<ClientFactory, AbortException> supplier =
        () -> {
          throw new AbortException("test");
        };
    FormValidation expected = FormValidation.error("test");
    FormValidation actual =
        descriptor(supplier).doCheckPublicKeyId(jenkins, "test", "test", "test", "test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckPublicKeyIdVerificationError() throws IOException {
    ClientFactory clientFactory =
        setupListPublicKeysClientFactory(ImmutableList.of(), Optional.of(new IOException("test")));
    FormValidation expected =
        FormValidation.error(Messages.BinAuthzBuildStep_PublicKeyIDFillError("test"));
    FormValidation actual =
        descriptor(() -> clientFactory).doCheckPublicKeyId(jenkins, "test", "test", "test", "test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckPublicKeyIdNoPublicKeys() throws IOException {
    ClientFactory clientFactory =
        setupListPublicKeysClientFactory(ImmutableList.of(), Optional.empty());
    FormValidation expected =
        FormValidation.error(Messages.BinAuthzBuildStep_PublicKeyIDNotForAttestor());
    FormValidation actual =
        descriptor(() -> clientFactory).doCheckPublicKeyId(jenkins, "test", "test", "test", "test");
    assertFormValidationEquals(expected, actual);
  }

  @Test
  public void testDoCheckPublicKeyId() throws IOException {
    ClientFactory clientFactory =
        setupListPublicKeysClientFactory(ImmutableList.of("other", "test"), Optional.empty());
    FormValidation expected = FormValidation.ok();
    FormValidation actual =
        descriptor(() -> clientFactory)
            .doCheckPublicKeyId(jenkins, "test", "test", "test", publicKeyId("test"));
    assertFormValidationEquals(expected, actual);
  }

  private static DescriptorImpl descriptor() {
    return Mockito.spy(new DescriptorImpl());
  }

  private static DescriptorImpl descriptor(Supplier<ClientFactory, AbortException> supplier) {
    DescriptorImpl descriptor = Mockito.spy(new DescriptorImpl());
    Mockito.doReturn(supplier).when(descriptor).clientFactory(any(), anyString());
    return descriptor;
  }

  private static ClientFactory setupListAttestorClientFactory(
      List<String> attestorIds, Optional<IOException> ioe) throws IOException {
    BinaryAuthorizationClient binaryAuthorizationClient =
        Mockito.mock(BinaryAuthorizationClient.class);
    if (ioe.isPresent()) {
      Mockito.when(binaryAuthorizationClient.listAttestors(anyString())).thenThrow(ioe.get());
    } else {
      Mockito.when(binaryAuthorizationClient.listAttestors(anyString()))
          .thenReturn(setUpItemList(attestorIds, n -> new Attestor().setName(n)));
    }
    ClientFactory clientFactory = Mockito.mock(ClientFactory.class);
    Mockito.when(clientFactory.binaryAuthorizationClient()).thenReturn(binaryAuthorizationClient);
    return clientFactory;
  }

  private static ClientFactory setupListPublicKeysClientFactory(
      List<String> publicKeyIds, Optional<IOException> ioe) throws IOException {
    BinaryAuthorizationClient binaryAuthorizationClient =
        Mockito.mock(BinaryAuthorizationClient.class);
    if (ioe.isPresent()) {
      Mockito.when(binaryAuthorizationClient.getAttestor(anyString(), anyString()))
          .thenThrow(ioe.get());
    } else {
      Attestor attestor =
          new Attestor()
              .setUserOwnedDrydockNote(
                  new UserOwnedDrydockNote()
                      .setPublicKeys(
                          setUpItemList(
                              publicKeyIds, k -> new AttestorPublicKey().setId(publicKeyId(k)))));
      Mockito.when(binaryAuthorizationClient.getAttestor(anyString(), anyString()))
          .thenReturn(attestor);
    }
    ClientFactory clientFactory = Mockito.mock(ClientFactory.class);
    Mockito.when(clientFactory.binaryAuthorizationClient()).thenReturn(binaryAuthorizationClient);
    return clientFactory;
  }

  private static String publicKeyId(String name) {
    return String.format(
        "projects/test/locations/global/keyRings/test/cryptoKeys/%s/cryptoKeyVersions/1", name);
  }
}
