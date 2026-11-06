/*
 * Copyright 2025 Apollo Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package com.ctrip.framework.apollo.openapi.util;

import com.ctrip.framework.apollo.common.exception.BadRequestException;
import com.google.common.base.CharMatcher;
import com.google.common.base.Joiner;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.net.InetAddresses;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

/**
 * Parses, normalizes and evaluates the client IP allowlist bound to an open api consumer token.
 * <p>
 * The allowlist is persisted as a comma separated list of IPv4/IPv6 addresses or CIDR blocks, e.g.
 * {@code 10.0.0.0/8,192.168.1.10,2001:db8::/32}. A blank allowlist means the token can be used
 * from any client.
 */
public final class ConsumerIpAllowlist {

  /**
   * Keep in sync with the length of {@code ConsumerToken.AllowedIps}.
   */
  public static final int MAX_LENGTH = 1024;

  private static final String SEPARATOR = ",";
  private static final Splitter SPLITTER =
      Splitter.on(CharMatcher.anyOf(",;\r\n\t ")).omitEmptyStrings().trimResults();
  private static final Joiner JOINER = Joiner.on(SEPARATOR);
  private static final int MATCHER_CACHE_MAX_SIZE = 1000;

  private static final Cache<String, List<IpAddressMatcher>> MATCHERS =
      CacheBuilder.newBuilder().maximumSize(MATCHER_CACHE_MAX_SIZE).build();

  private ConsumerIpAllowlist() {}

  /**
   * Validate and normalize the user provided allowlist entries.
   *
   * @param allowedIps entries provided by the user, each entry may contain multiple addresses
   *        separated by comma, semicolon or whitespace
   * @return the normalized allowlist ready to be persisted, or {@code null} if there is no entry
   * @throws BadRequestException if any entry is not a valid IP address or CIDR block, or the
   *         normalized allowlist is too long to be persisted
   */
  public static String normalize(Collection<String> allowedIps) {
    if (allowedIps == null || allowedIps.isEmpty()) {
      return null;
    }

    Set<String> entries = new LinkedHashSet<>();
    for (String allowedIp : allowedIps) {
      if (Strings.isNullOrEmpty(allowedIp)) {
        continue;
      }
      for (String entry : SPLITTER.split(allowedIp)) {
        validateEntry(entry);
        entries.add(entry);
      }
    }

    if (entries.isEmpty()) {
      return null;
    }

    String normalized = JOINER.join(entries);
    if (normalized.length() > MAX_LENGTH) {
      throw BadRequestException.allowedIpsTooLong(MAX_LENGTH);
    }
    return normalized;
  }

  /**
   * Split the persisted allowlist into entries, used for display purpose.
   *
   * @param allowedIps the persisted allowlist
   * @return the entries, or an empty list if the allowlist is blank
   */
  public static List<String> split(String allowedIps) {
    if (Strings.isNullOrEmpty(allowedIps)) {
      return Collections.emptyList();
    }
    return SPLITTER.splitToList(allowedIps);
  }

  /**
   * Check whether the client ip is allowed by the persisted allowlist.
   *
   * @param allowedIps the persisted allowlist, blank means no restriction
   * @param clientIp the client ip address
   * @return true if the allowlist is blank or the client ip matches any of its entries
   */
  public static boolean isAllowed(String allowedIps, String clientIp) {
    if (Strings.isNullOrEmpty(allowedIps)) {
      return true;
    }
    if (Strings.isNullOrEmpty(clientIp)) {
      return false;
    }

    for (IpAddressMatcher matcher : getMatchers(allowedIps)) {
      if (matches(matcher, clientIp)) {
        return true;
      }
    }
    return false;
  }

  private static boolean matches(IpAddressMatcher matcher, String clientIp) {
    try {
      return matcher.matches(clientIp);
    } catch (IllegalArgumentException ex) {
      // the client ip is not an ip literal, e.g. an unresolved host name
      return false;
    }
  }

  private static List<IpAddressMatcher> getMatchers(String allowedIps) {
    try {
      return MATCHERS.get(allowedIps, () -> parseMatchers(allowedIps));
    } catch (ExecutionException ex) {
      throw new IllegalStateException("Failed to parse allowed ips: " + allowedIps, ex.getCause());
    }
  }

  private static List<IpAddressMatcher> parseMatchers(String allowedIps) {
    List<IpAddressMatcher> matchers = new ArrayList<>();
    for (String entry : SPLITTER.split(allowedIps)) {
      IpAddressMatcher matcher = toMatcher(entry);
      // ignore the invalid entry which might be written to the database directly, so that
      // the remaining entries still take effect and the token is never opened up to everyone
      if (matcher != null) {
        matchers.add(matcher);
      }
    }
    return Collections.unmodifiableList(matchers);
  }

  private static void validateEntry(String entry) {
    if (toMatcher(entry) == null) {
      throw BadRequestException.allowedIpIsInvalid(entry);
    }
  }

  private static IpAddressMatcher toMatcher(String entry) {
    // IpAddressMatcher resolves the address with InetAddress.getByName, which accepts IPv4
    // shorthand such as "192.168.1" (192.168.0.1) or "10" (0.0.0.10). Require a full IP literal
    // so that an entry always means what it looks like.
    int slash = entry.indexOf('/');
    String address = slash < 0 ? entry : entry.substring(0, slash);
    if (!InetAddresses.isInetAddress(address)) {
      return null;
    }
    try {
      return new IpAddressMatcher(entry);
    } catch (IllegalArgumentException ex) {
      return null;
    }
  }
}
