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

package com.google.gke.auditor.system;

import static java.util.Map.entry;

import com.google.gke.auditor.configs.DetectorConfig;
import com.google.gke.auditor.system.DetectorRunner.RunResult;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Util class offering logging possibilities.
 * <p>
 * Offers possibilities of logging to command line in different colors.
 */
public class Logger {

  /**
   * Mapping between colors and their bold counterparts.
   */
  private static final Map<Color, Color> boldColors = Map.ofEntries(
      entry(Color.DEFAULT, Color.DEFAULT_BOLD),
      entry(Color.BLACK, Color.BLACK_BOLD),
      entry(Color.RED, Color.RED_BOLD),
      entry(Color.GREEN, Color.GREEN_BOLD),
      entry(Color.YELLOW, Color.YELLOW_BOLD),
      entry(Color.BLUE, Color.BLUE_BOLD)
  );
  /**
   * If true, the output will be colored.
   */
  private static boolean colored;
  /**
   * If true, the output will be non-verbose.
   */
  private static boolean quiet;

  /**
   * Initializes the Logger.
   * @param color if True, the output will be colored.
   * @param q     if True, the output is non-verbose
   */
  public static void init(boolean color, boolean q) {
    colored = color;
    quiet = q;
  }

  /**
   * Logs the message to the console.
   * @param message message to be logged
   */
  public static void log(String message) {
    System.out.println(message);
  }

  /**
   * Logs all messages of the {@link Builder} to the console with an appropriate number of indents
   * (tabs).
   * @param builder builder
   * @param indents number of indents
   */
  public static void log(Builder builder, int indents) {
    for (LoggerMessage message : builder.getMessages()) {
      log("\t".repeat(indents) + (colored ? message.getColoredMessage() : message.getMessage()));
    }

    for (Builder subBuilder : builder.getSubMessageBuilder()) {
      log(subBuilder, indents + 1);
    }
  }

  /**
   * Logs the {@link RunResult} result after scanning is done.
   * @param result run result
   */
  public static void logScanningDone(RunResult result) {
    log("Total count:");
    logScanningResult(result);
    log("Scanning done!");
  }

  /**
   * Logs the {@link RunResult} result.
   * @param result run result
   */
  public static void logScanningResult(RunResult result) {
    log("Potential vulnerabilities", result.getVulnerabilities().toString(),
        result.getVulnerabilities() == 0 ? Color.GREEN : Color.RED);
    if (result.getWarnings() > 0) {
      log("Warnings", result.getWarnings().toString(), Color.RED);
    }
    System.out.println();
  }

  /**
   * Logs a vulnerability.
   * <p>
   * Logs in red if output coloring is enabled.
   * @param vulnerability vulnerability to be logged
   */
  public static void logVulnerability(String vulnerability) {
    logError(vulnerability);
  }

  /**
   * Logs an error.
   * <p>
   * Logs in red if output coloring is enabled.
   * @param message message to be logged
   */
  public static void logError(String message) {
    log(message, Color.RED);
  }

  /**
   * Logs the detector result of a given detector.
   * <p>
   * Logs information about the detector and information about vulnerable assets found by the
   * detector.
   * @param detector     detector to be logged
   * @param assetReports vulnerable assets to be logged
   */
  public static void logDetectorResult(DetectorConfig detector, List<Builder> assetReports) {
    log(detector.getReport(quiet), 0);
    System.out.println();

    if (assetReports.size() > 0) {
      for (Builder report : assetReports) {
        log(report, 1);
      }
    }
    System.out.println();
  }

  /**
   * Logs the message.
   * @param key   message key
   * @param value message value
   * @param color message color
   */
  private static void log(String key, String value, Color color) {
    log(new LoggerMessage(key, value, color));
  }

  /**
   * Logs the message.
   * @param message message
   * @param color   message color
   */
  private static void log(String message, Color color) {
    log(new LoggerMessage(message, color));
  }

  /**
   * Logs the messages.
   * @param messages messages to be logged
   */
  private static void log(LoggerMessage... messages) {
    for (LoggerMessage message : messages) {
      log(colored ? message.getColoredMessage() : message.getMessage());
    }
  }

  /**
   * Returns a new instance of the {@link Builder}.
   */
  public static Builder builder() {
    return new Builder();
  }


  /**
   * Command Line Colors.
   */
  public enum Color {
    RESET("\033[0m"),
    DEFAULT(""),
    // Regular colors.
    BLACK("\033[0;30m"),
    RED("\033[0;31m"),
    GREEN("\033[0;32m"),
    YELLOW("\033[0;33m"),
    BLUE("\033[0;34m"),

    // Bold.
    DEFAULT_BOLD("\033[0;1m"),
    BLACK_BOLD("\033[1;30m"),
    RED_BOLD("\033[1;31m"),
    GREEN_BOLD("\033[1;32m"),
    YELLOW_BOLD("\033[1;33m"),
    BLUE_BOLD("\033[1;34m");

    private final String code;

    Color(String code) {
      this.code = code;
    }
  }

  /**
   * Builder for multiple {@link LoggerMessage}s printed out by the {@link Logger}.
   */
  public static class Builder {

    /**
     * Messages of the Builder.
     */
    private final List<LoggerMessage> messages = new ArrayList<>();

    /**
     * Sub-messages of this {@link Builder}. Sub-messages will be indented relative to the parent
     * builder by exactly one tab ("\t").
     */
    private List<Builder> subMessageBuilders = new ArrayList<>();

    public Builder addMessages(List<LoggerMessage> messages) {
      this.messages.addAll(messages);
      return this;
    }

    public Builder addMessage(String key, Color keyColor, String value, Color color) {
      messages.add(new LoggerMessage(key, keyColor, value, color));
      return this;
    }

    public Builder addMessage(String key, String value, Color color) {
      return addMessage(key, boldColors.get(color), value, color);
    }

    public Builder addMessage(String value, Color color) {
      return addMessage(null, null, value, color);
    }

    /**
     * Adds the message to the builder in default coloring.
     * @param key   message key
     * @param value message value
     * @return this
     */
    public Builder addMessage(String key, String value) {
      return addMessage(key, value, Color.DEFAULT);
    }

    /**
     * Adds the message to the builder without a key in default coloring.
     * @param value message
     * @return this
     */
    public Builder addMessage(String value) {
      return addMessage(value, Color.DEFAULT);
    }

    /**
     * Adding an empty message has the same effect to adding a new line, since a new line gets added
     * after every message in a {@link Builder}.
     * @return this
     */
    public Builder addLineBreak() {
      return addMessage("");
    }

    /**
     * Adds a sub-message to the builder. Sub-messages will be indented relative to the parent
     * builder by exactly one tab ("\t").
     * @param key   message key
     * @param value message value
     * @param color message color
     * @return this
     */
    public Builder addSubMessage(String key, String value, Color color) {
      if (subMessageBuilders.isEmpty()) {
        subMessageBuilders.add(new Logger.Builder());
      }
      this.subMessageBuilders.get(subMessageBuilders.size() - 1).addMessage(key, value, color);
      return this;
    }

    /**
     * Adds the sub-message to the builder in default coloring.
     * @param key   message key
     * @param value message value
     * @return this
     */
    public Builder addSubMessage(String key, String value) {
      return addSubMessage(key, value, Color.DEFAULT);
    }

    /**
     * Adding an empty sub-message has the same effect to adding a new line, since a new line gets
     * added after every message in a {@link Builder}.
     * @return this
     */
    public Builder addSubMessageLineBreak() {
      return addSubMessage(null, "");
    }

    public Builder addSubMessages(Builder builder) {
      this.subMessageBuilders.add(builder);
      return this;
    }

    public List<LoggerMessage> getMessages() {
      return messages;
    }

    public List<Builder> getSubMessageBuilder() {
      return subMessageBuilders;
    }

  }

  /**
   * A message printed out by the {@link Logger}.
   * <p>
   * Messages are formed in "Key: value" pairs. Both key and value colors can be defined. The key
   * will be bold.
   */
  static class LoggerMessage {

    private final String key;
    private final Color keyColor;

    private final String value;
    private final Color valueColor;

    public LoggerMessage(String message, Color color) {
      this(null, null, message, color);
    }

    public LoggerMessage(String key, String value, Color valueColor) {
      this(key, boldColors.get(valueColor), value, valueColor);
    }

    public LoggerMessage(String key, Color keyColor, String value, Color valueColor) {
      this.key = key;
      this.keyColor = keyColor;
      this.value = value;
      this.valueColor = valueColor;
    }

    /**
     * Returns the message in the format "Key: value" without coloring.
     */
    public String getMessage() {
      return (key == null ? "" : key  + ": ") + value;
    }

    /**
     * Returns the message in the format "Key: value", colored accordingly.
     */
    public String getColoredMessage() {
      return (keyColor != null ? keyColor.code : " ")
          + (key == null ? "" : key + ": ")
          + Color.RESET.code
          + (valueColor != null ? valueColor.code : " ")
          + value
          + Color.RESET.code;
    }

  }

}
