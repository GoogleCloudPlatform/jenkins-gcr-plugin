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

import static com.google.jenkins.plugins.containersecurity.client.ClientUtil.getClientFactory;
import static com.google.jenkins.plugins.containersecurity.util.DescriptorUtil.checkPermissions;
import static com.google.jenkins.plugins.containersecurity.util.DescriptorUtil.selectOption;
import static com.google.jenkins.plugins.containersecurity.util.DescriptorUtil.validateRequiredFields;
import static com.google.jenkins.plugins.containersecurity.util.DescriptorUtil.validateWithClientFactory;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.diffplug.common.base.Throwing.Specific;
import com.google.api.services.cloudresourcemanager.model.Project;
import com.google.cloud.graphite.platforms.plugin.client.ClientFactory;
import com.google.cloud.graphite.platforms.plugin.client.CloudResourceManagerClient;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.jenkins.plugins.containersecurity.client.ClientUtil;
import com.google.jenkins.plugins.containersecurity.client.ContainerSecurityScopeRequirement;
import com.google.jenkins.plugins.credentials.oauth.GoogleOAuth2Credentials;
import com.google.jenkins.plugins.credentials.oauth.GoogleRobotCredentials;
import hudson.AbortException;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.Util;
import hudson.model.AbstractProject;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.security.ACL;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import java.io.IOException;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.regex.Pattern;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.Setter;
import lombok.extern.java.Log;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;

/**
 * Runs Google Container Security plugin builds, allowing the user to configure a container URI and
 * run multiple related tasks to apply to that container, such as a {@link BinAuthzBuildStep} or
 * {@link VulnerabilityScanStep}.
 */
@Getter
@Setter(onMethod = @__(@DataBoundSetter))
@NoArgsConstructor(onConstructor = @__(@DataBoundConstructor))
@Log
public class GcspBuild extends Builder implements SimpleBuildStep, Serializable {
  public static final long serialVersionUID = 1L;

  private static final Pattern CONTAINER_DIGEST_MACRO_PATTERN =
      Pattern.compile("^\\$[a-zA-Z0-9_]+$");

  @VisibleForTesting
  static final Pattern CONTAINER_DIGEST_PATTERN = Pattern.compile("^sha256:[a-fA-F0-9]{64}$");

  @VisibleForTesting
  static final Pattern CONTAINER_TAG_PATTERN =
      Pattern.compile("^[a-zA-Z0-9_][a-zA-Z0-9_.\\-]{0,127}$");

  @VisibleForTesting
  static final String CONTAINER_URI_PATTERN_TEMPLATE =
      "^[a-z]*\\.?gcr.io/%s/([a-z0-9\\-]+[a-z0-9]/)*[a-z0-9\\-]+[a-z0-9]$";

  private String credentialsId;
  private String projectId;
  private String containerUri;
  private String containerQualifier;
  private boolean containerQualifierType = true;
  private List<AbstractGcspBuildStep> buildSteps;
  private transient String resolvedContainerUri;

  /** {@inheritDoc} */
  @Override
  public void perform(
      @NonNull Run<?, ?> run,
      @NonNull FilePath workspace,
      @NonNull Launcher launcher,
      @NonNull TaskListener taskListener)
      throws IOException, InterruptedException {
    log.info("Performing Google Container Registry Build steps");
    this.resolvedContainerUri = resolveContainerUri(run, taskListener);
    for (AbstractGcspBuildStep buildStep : buildSteps) {
      buildStep.perform(this, run, workspace, launcher, taskListener);
    }
  }

  private String resolveContainerUri(@NonNull Run<?, ?> run, @NonNull TaskListener taskListener)
      throws IOException, InterruptedException {
    String digest;
    if (containerQualifierType) {
      digest = Util.replaceMacro(containerQualifier, run.getEnvironment(taskListener));
    } else { // If it's a tag
      digest =
          getClientFactory(Jenkins.get(), credentialsId)
              .containerClient()
              .getDigest(containerUri, containerQualifier);
    }
    return String.format("%s@%s", containerUri, digest);
  }

  /** Descriptor implementation for {@link GcspBuild}. */
  @Extension
  public static class DescriptorImpl extends BuildStepDescriptor<Builder> {
    public DescriptorImpl() {
      super(GcspBuild.class);
    }

    /** {@inheritDoc} */
    public boolean isApplicable(Class<? extends AbstractProject> jobType) {
      return true;
    }

    /** {@inheritDoc} */
    @Override
    public String getDisplayName() {
      return Messages.GcspBuild_DisplayName();
    }

    @VisibleForTesting
    Specific.Supplier<ClientFactory, AbortException> clientFactory(
        Jenkins context, String credentialsId) {
      return () -> getClientFactory(context, credentialsId);
    }

    /**
     * Populates the credential selection dropdown with valid {@link GoogleOAuth2Credentials} IDs.
     *
     * @param context The {@link Jenkins} context.
     * @return The {@link ListBoxModel} containing the dropdown items.
     */
    public ListBoxModel doFillCredentialsIdItems(@AncestorInPath Jenkins context) {
      checkPermissions();
      if (!context.hasPermission(CredentialsProvider.VIEW)) {
        return new StandardListBoxModel();
      }
      return new StandardListBoxModel()
          .includeEmptyValue()
          .includeMatchingAs(
              ACL.SYSTEM,
              context,
              GoogleOAuth2Credentials.class,
              ImmutableList.of(),
              CredentialsMatchers.instanceOf(GoogleOAuth2Credentials.class));
    }

    /**
     * Validates that the provided credentialsId corresponds to a valid {@link
     * GoogleOAuth2Credentials}.
     *
     * @param context The {@link Jenkins} context.
     * @param credentialsId The ID of the service account credentials to check.
     * @return A {@link FormValidation}: either FormValidation.ok() if the provided credentialsId is
     *     valid, or FormValidation.error with a status message.
     */
    @RequirePOST
    public FormValidation doCheckCredentialsId(
        @AncestorInPath Jenkins context,
        @QueryParameter("credentialsId") final String credentialsId) {
      checkPermissions();
      return validateRequiredFields(
          ImmutableList.of(credentialsId),
          ImmutableList.of(Messages.GcspBuild_NoCredential()),
          () -> {
            GoogleRobotCredentials credentials;
            try {
              credentials =
                  ClientUtil.getRobotCredentials(context, ImmutableList.of(), credentialsId);
            } catch (AbortException ae) {
              return FormValidation.error(ae.getMessage());
            }

            try {
              credentials
                  .getGoogleCredential(new ContainerSecurityScopeRequirement())
                  .refreshToken();
              return FormValidation.ok();
            } catch (IOException | GeneralSecurityException e) {
              return FormValidation.error(Messages.GcspBuild_CredentialAuthFailed());
            }
          });
    }

    /**
     * Fills the project selection dropdown, selecting either the projectId or the first non-empty
     * project if available. If there is an error populating the dropdown, this will be a status
     * message corresponding to the issue.
     *
     * @param context The {@link Jenkins} context.
     * @param credentialsId The ID of the Service Account Credentials used to populate the dropdown.
     * @param projectId The project ID selected in the dropdown.
     * @return The {@link ListBoxModel} containing the dropdown items.
     */
    public ListBoxModel doFillProjectIdItems(
        @AncestorInPath Jenkins context,
        @QueryParameter("credentialsId") final String credentialsId,
        @QueryParameter("projectId") final String projectId) {
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
      } catch (IllegalArgumentException | AbortException e) {
        result.clear();
        result.add(e.getMessage(), "");
        return result;
      }

      try {
        CloudResourceManagerClient client = clientFactory.cloudResourceManagerClient();
        List<Project> projects = client.listProjects();
        projects.forEach(p -> result.add(p.getProjectId()));
        selectOption(result, projectId);
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
     * @param projectId The ID of the project selected in the dropdown.
     * @return A {@link FormValidation}: either FormValidation.ok() if projectId is usable by the
     *     provided credentials, or FormValidation.error with a status message indicating the issue
     *     the user needs to resolve.
     */
    public FormValidation doCheckProjectId(
        @AncestorInPath Jenkins context,
        @QueryParameter("credentialsId") final String credentialsId,
        @QueryParameter("projectId") final String projectId) {
      checkPermissions();
      return validateRequiredFields(
          ImmutableList.of(credentialsId, projectId),
          ImmutableList.of(
              Messages.GcspBuild_ProjectCredentialIDRequired(),
              Messages.GcspBuild_ProjectIDRequired()),
          () ->
              validateWithClientFactory(
                  clientFactory(context, credentialsId),
                  clientFactory -> {
                    try {
                      CloudResourceManagerClient client =
                          clientFactory.cloudResourceManagerClient();
                      List<Project> projects = client.listProjects();
                      if (projects.stream().noneMatch(p -> projectId.equals(p.getProjectId()))) {
                        return FormValidation.error(
                            Messages.GcspBuild_ProjectIDNotUnderCredential());
                      }
                      return FormValidation.ok();
                    } catch (IOException ioe) {
                      return FormValidation.error(
                          Messages.GcspBuild_ProjectIDVerificationError(ioe.getMessage()));
                    }
                  }));
    }

    /**
     * Validates that the provided URI matches the URI pattern including the projectId. See
     * https://cloud.google.com/container-registry/docs/overview#registry_name, omitting the tag or
     * digest at the end.
     *
     * @param projectId The ID of the project where the container is hosted.
     * @param containerUri The URI to check.
     * @return A {@link FormValidation}: FormValidation.ok() if the URI matches the pattern, or a
     *     FormValidation.error with a status message indicating the issue to resolve.
     */
    public FormValidation doCheckContainerUri(
        @QueryParameter("projectId") String projectId,
        @QueryParameter("containerUri") String containerUri) {
      checkPermissions();
      return validateRequiredFields(
          ImmutableList.of(containerUri, projectId),
          ImmutableList.of(
              Messages.GcspBuild_ContainerURIRequired(),
              Messages.GcspBuild_ContainerURIProjectIdRequired()),
          () -> {
            String uriPattern = String.format(CONTAINER_URI_PATTERN_TEMPLATE, projectId);
            Pattern pattern = Pattern.compile(uriPattern);
            if (!pattern.matcher(containerUri).find()) {
              return FormValidation.error(
                  Messages.GcspBuild_ContainerPatternNoMatch("URI", uriPattern));
            }
            return FormValidation.ok();
          });
    }

    /**
     * Populates the dropdown containing Container Qualifier types, either Digest or Tag.
     *
     * @return The {@link ListBoxModel} containing the dropdown items.
     */
    public ListBoxModel doFillContainerQualifierTypeItems() {
      checkPermissions();
      ListBoxModel result = new ListBoxModel();
      result.add("Digest", "true");
      result.add("Tag", "false");
      return result;
    }

    /**
     * Validates the provided Container Qualifier (Digest or Tag) against the provided type and
     * provided credentialsId. See https://docs.docker.com/registry/spec/api/#content-digests for
     * the valid Digest format. An expandable environment variable macro such as "$DIGEST" is valid
     * but might contain an invalid value at runtime. See
     * https://docs.docker.com/engine/reference/commandline/tag/ for the valid Tag format.
     *
     * @param credentialsId The ID of the Service Account Credentials.
     * @param containerQualifier The string containing the Digest or Tag.
     * @param containerQualifierType A boolean: true corresponds to Digest, false corresponds to Tag
     * @return A {@link FormValidation}: either FormValidation.ok() or FormValidation.warning if the
     *     containerQualifier is valid or FormValidation.error or with a status message indicating
     *     the issue to resolve.
     */
    public FormValidation doCheckContainerQualifier(
        @QueryParameter("credentialsId") final String credentialsId,
        @QueryParameter("containerQualifier") final String containerQualifier,
        @QueryParameter("containerQualifierType") final boolean containerQualifierType) {
      checkPermissions();
      if (Strings.isNullOrEmpty(containerQualifier)) {
        return FormValidation.error(Messages.GcspBuild_ContainerQualifierRequired());
      } else if (containerQualifierType) {
        if (CONTAINER_DIGEST_MACRO_PATTERN.matcher(containerQualifier).find()) {
          return FormValidation.warning(Messages.GcspBuild_ContainerDigestMacroWarning());
        } else if (!CONTAINER_DIGEST_PATTERN.matcher(containerQualifier).find()) {
          return FormValidation.error(
              Messages.GcspBuild_ContainerPatternNoMatch(
                  "Digest", CONTAINER_DIGEST_PATTERN.toString()));
        }
      } else {
        if (!CONTAINER_TAG_PATTERN.matcher(containerQualifier).find()) {
          return FormValidation.error(
              Messages.GcspBuild_ContainerPatternNoMatch("Tag", CONTAINER_TAG_PATTERN.toString()));
        } else if (Strings.isNullOrEmpty(credentialsId)) {
          return FormValidation.error(Messages.GcspBuild_ContainerTagCredentialIdRequired());
        }
      }
      return FormValidation.ok();
    }
  }
}
