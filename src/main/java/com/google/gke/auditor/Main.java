// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.gke.auditor;

import com.google.gke.auditor.system.DetectorRunner;
import com.google.gke.auditor.system.RunnerConfig;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

/**
 * Tool entry point.
 */
public class Main {

  /**
   * Parses the given CLI arguments and runs the tool accordingly.
   * @param args CLI arguments
   */
  public static void main(String[] args) {
    Options options = buildCLOptions();
    CommandLineParser parser = new DefaultParser();

    try {
      CommandLine cmd = parser.parse(options, args);
      RunnerConfig.Builder config = new RunnerConfig.Builder()
          .setRunIndividualAssets(cmd.hasOption("assets"))
          .setQuiet(cmd.hasOption("quiet"))
          .setColor(cmd.hasOption("color"))
          .setIncludeDefaults(cmd.hasOption("defaults"));

      if (cmd.hasOption("help")) {
        HelpFormatter formatter = new HelpFormatter();
        System.out.println("GKE Auditor\n"
            + "\tDetects a set of misconfigurations of Google Kubernetes Engine clusters.\n");
        formatter.printHelp("GKE Auditor", options, true);
      } else if (cmd.hasOption("all") ||
          (!cmd.hasOption("rbac") && !cmd.hasOption("iso") && !cmd.hasOption("psp"))) {
        DetectorRunner.run(config.build());
      } else {
        config.setRbacDetectorIndices(
            parseDetectorIndices(cmd.hasOption("rbac"), cmd.getOptionValues("rbac")))
            .setIsolationDetectorIndices(
                parseDetectorIndices(cmd.hasOption("iso"), cmd.getOptionValues("iso")))
            .setPspDetectorIndices(
                parseDetectorIndices(cmd.hasOption("psp"), cmd.getOptionValues("psp")));
        DetectorRunner.run(config.build());
      }

    } catch (ParseException | NumberFormatException e) {
      System.err.println("Malformed input arguments provided!");
    }

    System.exit(0);
  }

  private static Set<Integer> parseDetectorIndices(boolean hasOption, String[] indices)
      throws NumberFormatException {
    if (!hasOption) {
      return Collections.emptySet();
    }

    if (indices == null) {
      return null;
    }
    return Arrays.stream(indices).map(Integer::parseInt).collect(Collectors.toSet());
  }

  /**
   * Builds the tool CLI options.
   * @return built {@link Options}
   */
  private static Options buildCLOptions() {
    Options options = new Options();
    options.addOption("h", "help", false, "Print help information.");
    options.addOption("a", "all", false, "Run all detectors.");
    options.addOption("q", "quiet", false,
        "Prints out only misconfigurations, without additional detector info. Disabled by default.");
    options.addOption("d", "defaults", false,
        "Runs detectors including Kubernetes default assets. Disabled by default.");
    options.addOption("c", "color", false,
        "Turns on tool output coloring.");
    options.addOption(Option.builder("ast")
        .longOpt("assets")
        .hasArg(false)
        .desc("Run all detectors for each individual asset.")
        .build());
    options.addOption(Option.builder("r")
        .longOpt("rbac")
        .valueSeparator(',')
        .hasArgs()
        .optionalArg(true)
        .desc("Run RBAC (Role Based Access Control) detectors.\n "
            + "To run all detectors, omit the argument list.\n"
            + "To specify individual detectors to run, give a list of indices:\n"
            + "1. CLUSTER_ADMIN_ROLE_USED\n"
            + "2. SECRET_ACCESS_ALLOWED\n"
            + "3. WILDCARD_USED\n"
            + "4. CREATE_PODS_ALLOWED\n"
            + "5. AUTOMOUNT_SERVICE_ACCOUNT_TOKEN_ENABLED\n"
            + "6. ESCALATING_RESOURCES_REPORT\n")
        .build());
    options.addOption(Option.builder("i")
        .longOpt("iso")
        .valueSeparator(',')
        .hasArgs()
        .optionalArg(true)
        .desc("Run Node Isolation detectors.\n"
            + "To run all detectors, omit the argument list.\n"
            + "To specify individual detectors to run, give a list of indices:\n"
            + "1. NODE_SELECTOR_POD_REJECTED\n"
            + "2. NODE_TAINTS_POD_REJECTED\n"
            + "3. NODE_AFFINITY_POD_REJECTED\n")
        .build());
    options.addOption(Option.builder("p")
        .longOpt("psp")
        .valueSeparator(',')
        .hasArgs()
        .optionalArg(true)
        .desc(
            "Run PSP (Pod Security Policy) detectors.\n"
                + "To run all detectors, omit the argument list.\n"
                + "To specify individual detectors to run, give a list of indices:\n"
                + "1. PRIVILEGED_CONTAINERS\n"
                + "2. CONTAINERS_SHARING_HOST_PROCESS_ID_NAMESPACE\n"
                + "3. CONTAINERS_SHARING_HOST_IPC\n"
                + "4. CONTAINER_SHARING_HOST_NETWORK_NAMESPACE\n"
                + "5. CONTAINERS_ALLOW_PRIVILEGE_ESCALATION\n"
                + "6. ROOT_CONTAINERS_ADMISSION\n"
                + "7. CONTAINERS_NET_RAW_CAPABILITY\n"
                + "8. CONTAINERS_ADDED_CAPABILITIES\n"
                + "9. CONTAINERS_CAPABILITIES_ASSIGNED\n")
        .build());
    return options;
  }

}