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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ctrip.framework.apollo.common.exception.BadRequestException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link ConsumerIpAllowlist}.
 */
class ConsumerIpAllowlistTest {

  @Test
  void normalizeEmptyInputToNull() {
    assertNull(ConsumerIpAllowlist.normalize(null));
    assertNull(ConsumerIpAllowlist.normalize(Collections.emptyList()));
    assertNull(ConsumerIpAllowlist.normalize(Arrays.asList("", null, " \n ,")));
  }

  @Test
  void normalizeSplitsTrimsAndDeduplicates() {
    String normalized = ConsumerIpAllowlist.normalize(Arrays.asList(" 10.0.0.0/8 ,192.168.1.10",
        "192.168.1.10\n2001:db8::/32; ::1", "10.0.0.0/8"));

    assertEquals("10.0.0.0/8,192.168.1.10,2001:db8::/32,::1", normalized);
  }

  @Test
  void normalizeIsIdempotent() {
    String normalized = ConsumerIpAllowlist.normalize(List.of("10.0.0.0/8, 127.0.0.1"));

    assertEquals(normalized, ConsumerIpAllowlist.normalize(List.of(normalized)));
  }

  @Test
  void normalizeRejectsInvalidEntries() {
    for (String invalid : Arrays.asList("localhost", "10.0.0.300", "10.0.0.0/33", "10.0.0.0/", "*",
        "10.0.0.*")) {
      BadRequestException exception = assertThrows(BadRequestException.class,
          () -> ConsumerIpAllowlist.normalize(List.of("127.0.0.1", invalid)));
      assertEquals(BadRequestException.allowedIpIsInvalid(invalid).getMessage(),
          exception.getMessage());
    }
  }

  @Test
  void normalizeRejectsTooLongAllowlist() {
    StringBuilder allowedIps = new StringBuilder();
    for (int i = 0; i < 100; i++) {
      allowedIps.append("10.0.").append(i).append(".100,");
    }

    BadRequestException exception = assertThrows(BadRequestException.class,
        () -> ConsumerIpAllowlist.normalize(List.of(allowedIps.toString())));
    assertEquals(BadRequestException.allowedIpsTooLong(ConsumerIpAllowlist.MAX_LENGTH).getMessage(),
        exception.getMessage());
  }

  @Test
  void splitPersistedAllowlist() {
    assertTrue(ConsumerIpAllowlist.split(null).isEmpty());
    assertTrue(ConsumerIpAllowlist.split("").isEmpty());
    assertEquals(Arrays.asList("10.0.0.0/8", "::1"), ConsumerIpAllowlist.split("10.0.0.0/8,::1"));
  }

  @Test
  void blankAllowlistAllowsEveryone() {
    assertTrue(ConsumerIpAllowlist.isAllowed(null, "1.2.3.4"));
    assertTrue(ConsumerIpAllowlist.isAllowed("", null));
  }

  @Test
  void matchesAddressesAndCidrBlocks() {
    String allowedIps = "192.168.1.10,10.0.0.0/8,2001:db8::/32";

    assertTrue(ConsumerIpAllowlist.isAllowed(allowedIps, "192.168.1.10"));
    assertTrue(ConsumerIpAllowlist.isAllowed(allowedIps, "10.255.0.1"));
    assertTrue(ConsumerIpAllowlist.isAllowed(allowedIps, "2001:db8:0:0:0:0:0:1"));

    assertFalse(ConsumerIpAllowlist.isAllowed(allowedIps, "192.168.1.11"));
    assertFalse(ConsumerIpAllowlist.isAllowed(allowedIps, "11.0.0.1"));
    assertFalse(ConsumerIpAllowlist.isAllowed(allowedIps, "2001:db9::1"));
  }

  @Test
  void rejectsMissingOrMalformedClientIp() {
    assertFalse(ConsumerIpAllowlist.isAllowed("10.0.0.0/8", null));
    assertFalse(ConsumerIpAllowlist.isAllowed("10.0.0.0/8", ""));
    assertFalse(ConsumerIpAllowlist.isAllowed("10.0.0.0/8", "unknown"));
  }

  @Test
  void invalidPersistedEntriesNeverOpenUpTheToken() {
    assertTrue(ConsumerIpAllowlist.isAllowed("not-an-ip,10.0.0.0/8", "10.0.0.1"));
    assertFalse(ConsumerIpAllowlist.isAllowed("not-an-ip,10.0.0.0/8", "172.16.0.1"));
    assertFalse(ConsumerIpAllowlist.isAllowed("not-an-ip", "172.16.0.1"));
  }
}
