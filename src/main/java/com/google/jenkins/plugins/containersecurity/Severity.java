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

import lombok.Getter;

/** Severity levels for security vulnerabilities for use with the Container Analysis API. */
public enum Severity {
  UNSPECIFIED(0),
  LOW(1),
  MEDIUM(2),
  HIGH(3),
  CRITICAL(4),
  // This is not a real severity. Choose this to make all severities below the threshold.
  IGNORE(5);

  @Getter private int value;

  /**
   * The Container Analysis API returns some vulnerabilities with a severity of "null". This method
   * is used to handle this, and behaves identically to Severity.valueOf() for all other inputs.
   *
   * @param name The name of the Severity to retrieve.
   * @return Severity.UNSPECIFIED if name is null, or the Severity corresponding to the given name.
   * @throws IllegalArgumentException If the name is not one of the enumerated values.
   */
  public static Severity valueOfNullable(String name) {
    if (name == null) {
      return UNSPECIFIED;
    } else {
      return valueOf(name);
    }
  }

  Severity(int level) {
    this.value = level;
  }
}
