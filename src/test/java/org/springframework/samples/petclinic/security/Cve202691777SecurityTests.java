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

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.junit.jupiter.api.Test;

/**
 * Regression test for CVE-2026-91777: the tools.jackson.core:jackson-databind on the
 * runtime classpath must be at least 3.1.7, the first fixed version according to OSV.
 */
class Cve202691777SecurityTests {

	// CVE-2026-91777 is fixed in 3.1.7
	@Test
	void CVE_2026_91777_versionIsAtLeast_3_1_7() throws IOException {
		String actual = runtimeVersion();
		assertThat(isAtLeast(actual, "3.1.7"))
			.as("tools.jackson.core:jackson-databind on the classpath is %s, fixed in 3.1.7", actual)
			.isTrue();
	}

	private static String runtimeVersion() throws IOException {
		Properties props = new Properties();
		try (InputStream in = Thread.currentThread()
			.getContextClassLoader()
			.getResourceAsStream("META-INF/maven/tools.jackson.core/jackson-databind/pom.properties")) {
			assertThat(in).as("pom.properties of jackson-databind").isNotNull();
			props.load(in);
		}
		return props.getProperty("version");
	}

	static boolean isAtLeast(String actual, String minimum) {
		String[] a = actual.split("[.-]");
		String[] b = minimum.split("[.-]");
		for (int i = 0; i < b.length; i++) {
			int x = i < a.length ? Integer.parseInt(a[i].replaceAll("\\D.*", "0")) : 0;
			int y = Integer.parseInt(b[i]);
			if (x != y) {
				return x > y;
			}
		}
		return true;
	}

}
