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

import com.diffplug.common.base.Throwing.Specific;
import com.google.cloud.graphite.platforms.plugin.client.ClientFactory;
import com.google.common.annotations.VisibleForTesting;
import hudson.AbortException;
import hudson.DescriptorExtensionList;
import hudson.ExtensionPoint;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Describable;
import hudson.model.Descriptor;
import hudson.model.Run;
import hudson.model.TaskListener;
import java.io.IOException;
import java.io.Serializable;
import jenkins.model.Jenkins;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import org.kohsuke.stapler.DataBoundConstructor;

/** Build steps that run on a container image specified in a {@link GcspBuild}. */
@NoArgsConstructor(onConstructor = @__(@DataBoundConstructor))
public abstract class AbstractGcspBuildStep
    implements Describable<AbstractGcspBuildStep>, ExtensionPoint, Serializable {

  abstract void perform(
      @NonNull GcspBuild parent,
      @NonNull Run<?, ?> run,
      @NonNull FilePath workspace,
      @NonNull Launcher launcher,
      @NonNull TaskListener listener)
      throws IOException, InterruptedException;

  /** {@inheritDoc} */
  public AbstractGcspBuildStepDescriptor getDescriptor() {
    return (AbstractGcspBuildStepDescriptor) Jenkins.get().getDescriptor(getClass());
  }

  /** {@inheritDoc} */
  public DescriptorExtensionList<AbstractGcspBuildStep, Descriptor<AbstractGcspBuildStep>> all() {
    return Jenkins.get().getDescriptorList(AbstractGcspBuildStep.class);
  }

  /** Abstract descriptor for GcspBuild steps. */
  public abstract static class AbstractGcspBuildStepDescriptor
      extends Descriptor<AbstractGcspBuildStep> {
    protected AbstractGcspBuildStepDescriptor(
        @NonNull Class<? extends AbstractGcspBuildStep> clazz) {
      super(clazz);
    }

    @VisibleForTesting
    Specific.Supplier<ClientFactory, AbortException> clientFactory(
        Jenkins context, String credentialsId) {
      return () -> getClientFactory(context, credentialsId);
    }
  }
}
