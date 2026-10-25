/*
 * Copyright 2012-2025 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.samples.petclinic.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;

/**
 * Regression test for SAST-actuator-exposure: sensitive actuator endpoints must not be
 * reachable by an anonymous user.
 */
@SpringBootTest(webEnvironment = RANDOM_PORT)
@AutoConfigureTestRestTemplate
class ActuatorExposureSecurityTests {

	@Autowired
	private TestRestTemplate rest;

	@Autowired
	private Environment environment;

	@Test
	void sensitiveActuatorEndpointsAreNotExposed() {
		for (String endpoint : List.of("env", "beans", "configprops", "mappings", "threaddump", "loggers")) {
			HttpStatus status = HttpStatus
				.valueOf(this.rest.getForEntity("/actuator/" + endpoint, String.class).getStatusCode().value());
			assertThat(status).as("GET /actuator/%s", endpoint).isIn(HttpStatus.NOT_FOUND, HttpStatus.UNAUTHORIZED);
		}
	}

	@Test
	void exposureIncludeIsNotWildcard() {
		// "*" also exposes /actuator/heapdump (a dump of the JVM memory)
		String include = this.environment.getProperty("management.endpoints.web.exposure.include", "");
		assertThat(List.of(include.split(",")).stream().map(String::trim).toList()).doesNotContain("*", "heapdump",
				"env");
	}

}
