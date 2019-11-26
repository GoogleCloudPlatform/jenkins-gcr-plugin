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

import com.diffplug.common.base.Throwing.Specific;
import com.google.cloud.graphite.platforms.plugin.client.ClientFactory;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import hudson.AbortException;
import hudson.model.Job;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.ListBoxModel.Option;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Supplier;
import jenkins.model.Jenkins;
import lombok.NonNull;

// TODO(stephenshank): Migrate to 'jenkins' module of gcp-plugin-core-java
/** Utilities for common tasks when writing Descriptors for configuration. */
public class DescriptorUtil {

  // TODO(stephenshank): Use GCE plugin for reference when transferring to gcp-plugin-core-java.
  /** Checks that the current context has the ability to configure a Permission. */
  public static void checkPermissions() {
    Jenkins jenkins = Jenkins.getInstanceOrNull();
    if (jenkins != null) {
      jenkins.checkPermission(Job.CONFIGURE);
    }
  }

  /**
   * Selects an item from the provided dropdown list items. If the provided value does not exist in
   * the list, selects the first available option.
   *
   * @param listBoxModel The list of dropdown options.
   * @param optionValue The value to select if it exists.
   */
  public static void selectOption(ListBoxModel listBoxModel, String optionValue) {
    if (listBoxModel == null) {
      return;
    }
    Optional<Option> item;
    if (!Strings.isNullOrEmpty(optionValue)) {
      item = listBoxModel.stream().filter(option -> optionValue.equals(option.value)).findFirst();
      if (item.isPresent()) {
        item.get().selected = true;
        return;
      }
    }
    item = listBoxModel.stream().filter(option -> !Strings.isNullOrEmpty(option.value)).findFirst();
    item.ifPresent(i -> i.selected = true);
  }

  /**
   * Performs a common part of validating form inputs: verifying that a list of required fields is
   * not null or empty. If one of the fields is null or empty, the corresponding message will be the
   * message of the returned FormValidation.error. Otherwise, it will return the result of the
   * provided callback.
   *
   * @param fields A list of values for form entries. Must be non-null and have the same length as
   *     messages.
   * @param messages A list of messages to return if the corresponding entry is null or empty. Must
   *     be non-null and have the same length as fields.
   * @param callback A function taking no arguments and returning a FormValidation. Usually this
   *     should be a closure that contains the rest of the form validation logic after verifying the
   *     inputs are present. Must be non-null.
   * @return The FormValidation.error with a message indicating the corresponding field is null or
   *     empty, or the result of callback.get() if no fields are null or empty.
   */
  public static FormValidation validateRequiredFields(
      @NonNull List<String> fields,
      @NonNull List<String> messages,
      @NonNull Supplier<FormValidation> callback) {
    Preconditions.checkState(fields.size() == messages.size());
    for (int i = 0; i < fields.size(); i++) {
      if (Strings.isNullOrEmpty(fields.get(i))) {
        return FormValidation.error(messages.get(i));
      }
    }
    return callback.get();
  }

  /**
   * Performs FormValidation that requires the use of a {@link ClientFactory}. If there is a problem
   * with getting the {@link ClientFactory} then a FormValidation.error with the associated issue
   * will be returned, otherwise it will return the result of the provided callback.
   *
   * @param clientFactorySupplier A function that provides a {@link ClientFactory} when called.
   * @param callback A function taking a {@link ClientFactory} and returning a FormValidation,
   *     usually a closure containing the remainder of the Form Validation logic. Must be non-null.
   * @return Either a FormValidation.error with a message indicating the error for retrieving the
   *     {@link ClientFactory}, or the result of the provided callback.
   */
  public static FormValidation validateWithClientFactory(
      @NonNull Specific.Supplier<ClientFactory, AbortException> clientFactorySupplier,
      @NonNull Function<ClientFactory, FormValidation> callback) {
    ClientFactory clientFactory;
    try {
      clientFactory = clientFactorySupplier.get();
    } catch (IllegalArgumentException | AbortException e) {
      return FormValidation.error(e.getMessage());
    }
    return callback.apply(clientFactory);
  }

  /*
   * TODO(stephenshank): Add methods similar to validateRequiredFields and validateWithClientFactory
   *    for use with the doFill...Items methods in the descriptors.
   */
}
