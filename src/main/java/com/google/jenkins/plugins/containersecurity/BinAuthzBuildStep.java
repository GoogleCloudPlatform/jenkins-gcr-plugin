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

import static com.google.cloud.graphite.platforms.plugin.client.util.ClientUtil.nameFromSelfLink;
import static com.google.jenkins.plugins.containersecurity.client.ClientUtil.getClientFactory;
import static com.google.jenkins.plugins.containersecurity.util.DescriptorUtil.checkPermissions;
import static com.google.jenkins.plugins.containersecurity.util.DescriptorUtil.selectOption;
import static com.google.jenkins.plugins.containersecurity.util.DescriptorUtil.validateRequiredFields;
import static com.google.jenkins.plugins.containersecurity.util.DescriptorUtil.validateWithClientFactory;

import com.google.api.services.binaryauthorization.v1beta1.model.Attestor;
import com.google.api.services.binaryauthorization.v1beta1.model.AttestorPublicKey;
import com.google.api.services.cloudresourcemanager.model.Project;
import com.google.api.services.containeranalysis.v1beta1.model.Occurrence;
import com.google.cloud.graphite.platforms.plugin.client.BinaryAuthorizationClient;
import com.google.cloud.graphite.platforms.plugin.client.ClientFactory;
import com.google.cloud.graphite.platforms.plugin.client.CloudKMSClient;
import com.google.cloud.graphite.platforms.plugin.client.CloudResourceManagerClient;
import com.google.cloud.graphite.platforms.plugin.client.ContainerAnalysisClient;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import hudson.AbortException;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.RelativePath;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import jenkins.model.Jenkins;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.Setter;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

/**
 * A step for a {@link GcspBuild} that creates attestation for a container image with a specified
 * Attestor. These attestations are submitted as Occurrences of the Attestor note to the Container
 * Analysis API for the container image, so that you can gate GKE deployments on whether the
 * container image has the required attestation.
 */
@Getter
@Setter(onMethod = @__(@DataBoundSetter))
@NoArgsConstructor(onConstructor = @__(@DataBoundConstructor))
public class BinAuthzBuildStep extends AbstractGcspBuildStep {
  private static final int PROJECT_ID_INDEX = 1;
  private static final int LOCATION_INDEX = 3;
  private static final int KEY_RING_INDEX = 5;
  private static final int CRYPTO_KEY_INDEX = 7;
  private static final int CRYPTO_KEY_VERSION_INDEX = 9;
  private static final int PUBLIC_KEY_ID_ELEMENTS_LENGTH = 10;

  private String attestorProjectId;
  private String attestorId;
  private String publicKeyId;

  private String sign(CloudKMSClient client, String payload) throws IOException {
    String[] keyComponents = publicKeyId.split("/");
    return client.asymmetricSign(
        keyComponents[PROJECT_ID_INDEX],
        keyComponents[LOCATION_INDEX],
        keyComponents[KEY_RING_INDEX],
        keyComponents[CRYPTO_KEY_INDEX],
        keyComponents[CRYPTO_KEY_VERSION_INDEX],
        payload);
  }

  void perform(
      @NonNull GcspBuild parent,
      @NonNull Run<?, ?> run,
      @NonNull FilePath workspace,
      @NonNull Launcher launcher,
      @NonNull TaskListener listener)
      throws IOException, InterruptedException {
    String containerUri = parent.getResolvedContainerUri();
    listener
        .getLogger()
        .println(
            Messages.BinAuthzBuildStep_IntroMessage(attestorProjectId, attestorId, containerUri));
    ClientFactory clientFactory;
    try {
      clientFactory = getClientFactory(Jenkins.get(), parent.getCredentialsId());
    } catch (IllegalArgumentException | AbortException ae) {
      listener.getLogger().println("Failed to get credentials id from parent: " + ae.getMessage());
      return;
    }

    Occurrence attestation = null;
    try {
      BinaryAuthorizationClient binaryAuthorizationClient =
          clientFactory.binaryAuthorizationClient();
      CloudKMSClient cloudKMSClient = clientFactory.cloudKMSClient();
      ContainerAnalysisClient containerAnalysisClient = clientFactory.containerAnalysisClient();
      String payload = binaryAuthorizationClient.generateAttestationPayload(containerUri);
      String signature = sign(cloudKMSClient, payload);
      // TODO(stephenshank): Move "https://" and "-note" implementation details into client.
      attestation =
          containerAnalysisClient.createAttestation(
              parent.getProjectId(),
              "https://" + containerUri,
              attestorProjectId,
              attestorId + "-note",
              signature,
              publicKeyId,
              Base64.getEncoder().encodeToString(payload.getBytes(StandardCharsets.UTF_8)));
    } catch (IllegalArgumentException iae) {
      listener.getLogger().println("Failed to create attestation: " + iae.getMessage());
      throw iae;
    } catch (IOException ioe) {
      if (ioe.getMessage().contains("409 Conflict")) {
        listener.getLogger().println("Attestation already exists: " + ioe.getMessage());
        return;
      }
      listener.getLogger().println("Failed to create attestation: " + ioe.getMessage());
      throw ioe;
    }

    // TODO(stephenshank): Display information about created attestation.
    listener.getLogger().println(attestation.getName());
    listener
        .getLogger()
        .println(
            attestation
                .getAttestation()
                .getAttestation()
                .getGenericSignedAttestation()
                .toPrettyString());
  }

  /** Descriptor implementation for {@link BinAuthzBuildStep}. */
  @Extension
  public static class DescriptorImpl extends AbstractGcspBuildStepDescriptor {
    /** Constructor for {@link BinAuthzBuildStep.DescriptorImpl}. */
    public DescriptorImpl() {
      super(BinAuthzBuildStep.class);
    }

    /** {@inheritDoc} */
    @Override
    public String getDisplayName() {
      return Messages.BinAuthzBuildStep_DisplayName();
    }

    /**
     * Fills the project selection drop down, selecting either the attestorProjectId or the first
     * non-empty project if available. If there is an error populating the dropdown, this will be a
     * status message corresponding to the issue.
     *
     * @param context The {@link Jenkins} context.
     * @param credentialsId The ID of the Service Account Credentials used to populate the dropdown.
     * @param attestorProjectId The project ID selected in the dropdown, or empty if this is the
     *     first time.
     * @return The {@link ListBoxModel} containing the dropdown items.
     */
    public ListBoxModel doFillAttestorProjectIdItems(
        @AncestorInPath Jenkins context,
        @QueryParameter("credentialsId") @RelativePath("..") final String credentialsId,
        @QueryParameter("attestorProjectId") final String attestorProjectId) {
      checkPermissions();
      ListBoxModel result = new ListBoxModel();
      result.add("");
      if (Strings.isNullOrEmpty(credentialsId)) {
        result.clear();
        result.add(Messages.GcspBuild_ProjectCredentialIDRequired(), "");
        return result;
      }

      ClientFactory clientFactory;
      try {
        clientFactory = clientFactory(context, credentialsId).get();
      } catch (IllegalArgumentException | AbortException ae) {
        result.clear();
        result.add(ae.getMessage(), "");
        return result;
      }

      try {
        CloudResourceManagerClient client = clientFactory.cloudResourceManagerClient();
        List<Project> projects = client.listProjects();
        projects.forEach(p -> result.add(p.getProjectId()));
        selectOption(result, attestorProjectId);
        return result;
      } catch (IOException ioe) {
        result.clear();
        result.add(Messages.GcspBuild_ProjectIDFillError(ioe.getMessage()), "");
        return result;
      }
    }

    /**
     * Validates that the provided service account credentials has permission to access the provided
     * project, informing the user of any issues that need to be resolved.
     *
     * @param context The {@link Jenkins} context.
     * @param credentialsId The ID of the Service Account Credentials used to populate the dropdown.
     * @param attestorProjectId The ID of the project selected in the dropdown.
     * @return A {@link FormValidation}: either FormValidation.ok() if attestorProjectId is usable
     *     by the provided credentials, or FormValidation.error with a status message indicating the
     *     issue the user needs to resolve.
     */
    public FormValidation doCheckAttestorProjectId(
        @AncestorInPath Jenkins context,
        @QueryParameter("credentialsId") @RelativePath("..") final String credentialsId,
        @QueryParameter("attestorProjectId") final String attestorProjectId) {
      checkPermissions();
      return validateRequiredFields(
          ImmutableList.of(credentialsId, attestorProjectId),
          ImmutableList.of(
              Messages.GcspBuild_ProjectCredentialIDRequired(),
              Messages.BinAuthzBuildStep_AttestorProjectIDRequired()),
          () ->
              validateWithClientFactory(
                  clientFactory(context, credentialsId),
                  clientFactory -> {
                    try {
                      if (clientFactory.cloudResourceManagerClient().listProjects().stream()
                          .noneMatch(p -> p.getProjectId().equals(attestorProjectId))) {
                        return FormValidation.error(
                            Messages.GcspBuild_ProjectIDNotUnderCredential());
                      }
                      return FormValidation.ok();
                    } catch (IllegalArgumentException | IOException ioe) {
                      return FormValidation.error(
                          Messages.GcspBuild_ProjectIDVerificationError(ioe.getMessage()));
                    }
                  }));
    }

    /**
     * Fills the atttestor selection drop down, selecting either the attestorId or the first
     * non-empty attestor if available. If there is an error populating the dropdown, this will be a
     * status message corresponding to the issue.
     *
     * @param context The {@link Jenkins} context.
     * @param credentialsId The ID of the Service Account Credentials used to populate the dropdown.
     * @param attestorProjectId The ID of the project where the attestor is hosted.
     * @param attestorId The attestor selected, or empty if this is the first time.
     * @return The {@link ListBoxModel} containing the dropdown items.
     */
    public ListBoxModel doFillAttestorIdItems(
        @AncestorInPath Jenkins context,
        @QueryParameter("credentialsId") @RelativePath("..") final String credentialsId,
        @QueryParameter("attestorProjectId") final String attestorProjectId,
        @QueryParameter("attestorId") final String attestorId) {
      checkPermissions();
      ListBoxModel result = new ListBoxModel();
      result.add("");
      if (Strings.isNullOrEmpty(credentialsId)) {
        result.clear();
        result.add(Messages.GcspBuild_ProjectCredentialIDRequired(), "");
        return result;
      } else if (Strings.isNullOrEmpty(attestorProjectId)) {
        result.clear();
        result.add(Messages.BinAuthzBuildStep_AttestorIDProjectIDRequired(), "");
        return result;
      }

      ClientFactory clientFactory;
      try {
        clientFactory = clientFactory(context, credentialsId).get();
      } catch (IllegalArgumentException | AbortException ae) {
        result.clear();
        result.add(ae.getMessage(), "");
        return result;
      }

      try {
        BinaryAuthorizationClient client = clientFactory.binaryAuthorizationClient();
        List<Attestor> attestors = client.listAttestors(attestorProjectId);
        attestors.forEach(a -> result.add(nameFromSelfLink(a.getName())));
        selectOption(result, attestorId);
        return result;
      } catch (IllegalArgumentException | IOException e) {
        result.clear();
        result.add(Messages.BinAuthzBuildStep_AttestorIDFillError(e.getMessage()), "");
        return result;
      }
    }

    /**
     * Validates that the provided service account credentials has permission to access the provided
     * attestor in the provided project, informing the user of any issues that need to be resolved.
     *
     * @param context The {@link Jenkins} context.
     * @param credentialsId The ID of the Service Account Credentials used to validate.
     * @param attestorProjectId The ID of the project where the attestor is hosted.
     * @param attestorId The ID of the attestor to check.
     * @return A {@link FormValidation}: either FormValidation.ok() if attestorId is an attestor in
     *     the provided project, or FormValidation.error with a status message indicating the issue
     *     the user needs to resolve.
     */
    public FormValidation doCheckAttestorId(
        @AncestorInPath Jenkins context,
        @QueryParameter("credentialsId") @RelativePath("..") final String credentialsId,
        @QueryParameter("attestorProjectId") final String attestorProjectId,
        @QueryParameter("attestorId") final String attestorId) {
      checkPermissions();
      return validateRequiredFields(
          ImmutableList.of(credentialsId, attestorProjectId, attestorId),
          ImmutableList.of(
              Messages.GcspBuild_ProjectCredentialIDRequired(),
              Messages.BinAuthzBuildStep_AttestorIDProjectIDRequired(),
              Messages.BinAuthzBuildStep_AttestorIDRequired()),
          () ->
              validateWithClientFactory(
                  clientFactory(context, credentialsId),
                  clientFactory -> {
                    try {
                      if (clientFactory.binaryAuthorizationClient().listAttestors(attestorProjectId)
                          .stream()
                          .noneMatch(p -> nameFromSelfLink(p.getName()).equals(attestorId))) {
                        return FormValidation.error(
                            Messages.BinAuthzBuildStep_AttestorIDNotUnderProject());
                      }
                      return FormValidation.ok();
                    } catch (IllegalArgumentException | IOException ioe) {
                      return FormValidation.error(
                          Messages.BinAuthzBuildStep_AttestorIDVerificationError(ioe.getMessage()));
                    }
                  }));
    }

    /**
     * Fills the public key selection drop down, selecting either the publicKeyId or the first
     * non-empty public key if available. If there is an error populating the dropdown, this will be
     * a status message corresponding to the issue.
     *
     * @param context The {@link Jenkins} context.
     * @param credentialsId The ID of the Service Account Credentials used to populate the dropdown.
     * @param attestorProjectId The ID of the project where the attestor is hosted.
     * @param attestorId The ID of the attestor to query for public keys.
     * @param publicKeyId The ID of the selected public key, or empty if this is the first time.
     * @return The {@link ListBoxModel} containing the dropdown items.
     */
    public ListBoxModel doFillPublicKeyIdItems(
        @AncestorInPath Jenkins context,
        @QueryParameter("credentialsId") @RelativePath("..") final String credentialsId,
        @QueryParameter("attestorProjectId") final String attestorProjectId,
        @QueryParameter("attestorId") final String attestorId,
        @QueryParameter("publicKeyId") final String publicKeyId) {
      checkPermissions();
      ListBoxModel result = new ListBoxModel();
      result.add("");
      if (Strings.isNullOrEmpty(credentialsId)) {
        result.clear();
        result.add(Messages.GcspBuild_ProjectCredentialIDRequired(), "");
        return result;
      } else if (Strings.isNullOrEmpty(attestorProjectId)) {
        result.clear();
        result.add(Messages.BinAuthzBuildStep_PublicKeyIDProjectIdRequired(), "");
        return result;
      } else if (Strings.isNullOrEmpty(attestorId)) {
        result.clear();
        result.add(Messages.BinAuthzBuildStep_PublicKeyIDAttestorIDRequired(), "");
        return result;
      }

      ClientFactory clientFactory;
      try {
        clientFactory = clientFactory(context, credentialsId).get();
      } catch (IllegalArgumentException | AbortException ae) {
        result.clear();
        result.add(ae.getMessage(), "");
        return result;
      }

      try {
        Attestor attestor =
            clientFactory.binaryAuthorizationClient().getAttestor(attestorProjectId, attestorId);
        if (attestor == null) {
          result.clear();
          result.add(Messages.BinAuthzBuildStep_AttestorIDNotUnderProject());
          return result;
        }
        List<AttestorPublicKey> publicKeys = attestor.getUserOwnedDrydockNote().getPublicKeys();
        publicKeys.stream()
            .filter(
                k ->
                    k.getId().contains("projects/")
                        && k.getId().split("/").length == PUBLIC_KEY_ID_ELEMENTS_LENGTH)
            .forEach(k -> result.add(k.getId()));
        selectOption(result, publicKeyId);
        return result;
      } catch (IllegalArgumentException | IOException e) {
        result.clear();
        result.add(Messages.BinAuthzBuildStep_PublicKeyIDFillError(e.getMessage()));
        return result;
      }
    }

    /**
     * Validates that the provided public key ID is one of the keys used for signing attestations on
     * behalf of the the provided attestor, informing the user of any issues that need to be
     * resolved.
     *
     * @param context The {@link Jenkins} context.
     * @param credentialsId The ID of the Service Account Credentials used to validate.
     * @param attestorProjectId The ID of the project where the attestor is hosted.
     * @param attestorId The ID of the attestor.
     * @param publicKeyId The ID of the public key to check.
     * @return A {@link FormValidation}: either FormValidation.ok() if the provided public key ID is
     *     able to sign on behalf of the provided attestor, or FormValidation.error with a status
     *     message indicating the issue the user needs to resolve.
     */
    public FormValidation doCheckPublicKeyId(
        @AncestorInPath Jenkins context,
        @QueryParameter("credentialsId") @RelativePath("..") final String credentialsId,
        @QueryParameter("attestorProjectId") final String attestorProjectId,
        @QueryParameter("attestorId") final String attestorId,
        @QueryParameter("publicKeyId") final String publicKeyId) {
      checkPermissions();
      return validateRequiredFields(
          ImmutableList.of(credentialsId, attestorProjectId, attestorId, publicKeyId),
          ImmutableList.of(
              Messages.GcspBuild_ProjectCredentialIDRequired(),
              Messages.BinAuthzBuildStep_PublicKeyIDProjectIdRequired(),
              Messages.BinAuthzBuildStep_PublicKeyIDAttestorIDRequired(),
              Messages.BinAuthzBuildStep_PublicKeyIDRequired()),
          () ->
              validateWithClientFactory(
                  clientFactory(context, credentialsId),
                  clientFactory -> {
                    try {
                      if (clientFactory.binaryAuthorizationClient()
                          .getAttestor(attestorProjectId, attestorId).getUserOwnedDrydockNote()
                          .getPublicKeys().stream()
                          .noneMatch(k -> publicKeyId.equals(k.getId()))) {
                        return FormValidation.error(
                            Messages.BinAuthzBuildStep_PublicKeyIDNotForAttestor());
                      }
                      return FormValidation.ok();
                    } catch (IllegalArgumentException | IOException e) {
                      return FormValidation.error(
                          Messages.BinAuthzBuildStep_PublicKeyIDFillError(e.getMessage()));
                    }
                  }));
    }
  }
}
