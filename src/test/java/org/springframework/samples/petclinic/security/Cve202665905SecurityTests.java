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

import org.apache.catalina.util.ServerInfo;
import org.junit.jupiter.api.Test;

/**
 * Regression test for CVE-2026-65905: the tomcat-embed-core (Apache Tomcat) on the
 * runtime classpath must be at least 11.0.25, the first fixed version according to OSV.
 */
class Cve202665905SecurityTests {

	// CVE-2026-65905 is fixed in 11.0.25
	@Test
	void CVE_2026_65905_versionIsAtLeast_11_0_25() throws IOException {
		String actual = runtimeVersion();
		assertThat(isAtLeast(actual, "11.0.25"))
			.as("tomcat-embed-core (Apache Tomcat) on the classpath is %s, fixed in 11.0.25", actual)
			.isTrue();
	}

	private static String runtimeVersion() throws IOException {
		return ServerInfo.getServerNumber();
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
