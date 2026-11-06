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
package com.ctrip.framework.apollo.portal.entity.vo.consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Arrays;
import java.util.Collections;
import org.junit.jupiter.api.Test;

/**
 * Tests the json binding of {@link ConsumerCreateRequestVO}.
 */
class ConsumerCreateRequestVOTest {

  private final ObjectMapper objectMapper = new ObjectMapper();

  @Test
  void bindAllowedIpsFromArray() throws Exception {
    ConsumerCreateRequestVO request =
        objectMapper.readValue("{\"appId\":\"someApp\",\"allowedIps\":[\"10.0.0.0/8\",\"::1\"]}",
            ConsumerCreateRequestVO.class);

    assertEquals(Arrays.asList("10.0.0.0/8", "::1"), request.getAllowedIps());
  }

  @Test
  void bindAllowedIpsFromSingleString() throws Exception {
    ConsumerCreateRequestVO request =
        objectMapper.readValue("{\"appId\":\"someApp\",\"allowedIps\":\"10.0.0.0/8, ::1\"}",
            ConsumerCreateRequestVO.class);

    assertEquals(Collections.singletonList("10.0.0.0/8, ::1"), request.getAllowedIps());
  }

  @Test
  void allowedIpsAreOptional() throws Exception {
    ConsumerCreateRequestVO request =
        objectMapper.readValue("{\"appId\":\"someApp\"}", ConsumerCreateRequestVO.class);

    assertNull(request.getAllowedIps());
  }
}
