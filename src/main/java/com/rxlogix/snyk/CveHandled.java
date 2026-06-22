package com.rxlogix.snyk;

import java.util.Arrays;
import java.util.List;

public enum CveHandled {
	
	CVE202438816(
			"CVE-2024-38816", 
			Arrays.asList("org.springframework:spring-webmvc"),
			Arrays.asList("5.3.39-rxlogix-1", "5.3.39-rxlogix-2", "5.3.39-rxlogix-3", "5.3.39-rxlogix-4", "5.3.39-rxlogix-5", "5.3.39-rxlogix-6")),
	CVE202438819(
			"CVE-2024-38819", 
			Arrays.asList("org.springframework:spring-webmvc"),
			Arrays.asList("5.3.39-rxlogix-1", "5.3.39-rxlogix-2", "5.3.39-rxlogix-3", "5.3.39-rxlogix-4", "5.3.39-rxlogix-5", "5.3.39-rxlogix-6")),
	CVE202438820(
			"CVE-2024-38820", 
			Arrays.asList(
					"org.springframework:spring-context",
					"org.springframework:spring-websocket",
					"org.springframework:spring-core",
					"org.springframework:spring-web",
					"org.springframework:spring-webmvc"),
			Arrays.asList("5.3.39-rxlogix-1", "5.3.39-rxlogix-2", "5.3.39-rxlogix-3", "5.3.39-rxlogix-4", "5.3.39-rxlogix-5", "5.3.39-rxlogix-6")),
	CVE202438828(
			"CVE-2024-38828", 
			Arrays.asList("org.springframework:spring-webmvc"),
			Arrays.asList("5.3.39-rxlogix-2", "5.3.39-rxlogix-3", "5.3.39-rxlogix-4", "5.3.39-rxlogix-5", "5.3.39-rxlogix-6")),
	CVE202541242(
			"CVE-2025-41242", 
			Arrays.asList("org.springframework:spring-beans"),
			Arrays.asList("5.3.39-rxlogix-3", "5.3.39-rxlogix-4", "5.3.39-rxlogix-5", "5.3.39-rxlogix-6")),
	CVE202541249(
			"CVE-2025-41249", 
			Arrays.asList("org.springframework:spring-core"),
			Arrays.asList("5.3.39-rxlogix-4", "5.3.39-rxlogix-5", "5.3.39-rxlogix-6")),
	CVE202541254(
			"CVE-2025-41254",
			Arrays.asList("org.springframework:spring-websocket"),
			Arrays.asList("5.3.39-rxlogix-5", "5.3.39-rxlogix-6")),
	CVE202622735(
			"CVE-2026-22735",
			Arrays.asList("org.springframework:spring-webmvc", "org.springframework:spring-web"),
			Arrays.asList("5.3.39-rxlogix-6")),
	CVE202622737(
			"CVE-2026-22737",
			Arrays.asList("org.springframework:spring-webmvc", "org.springframework:spring-webflux"),
			Arrays.asList("5.3.39-rxlogix-6")),
	CVE202622740(
			"CVE-2026-22740",
			Arrays.asList("org.springframework:spring-web"),
			Arrays.asList("5.3.39-rxlogix-6")),
	CVE202622741(
			"CVE-2026-22741",
			Arrays.asList("org.springframework:spring-webmvc", "org.springframework:spring-webflux"),
			Arrays.asList("5.3.39-rxlogix-6")),
	CVE202622745(
			"CVE-2026-22745",
			Arrays.asList("org.springframework:spring-core"),
			Arrays.asList("5.3.39-rxlogix-6")),
	CVE202412801(
			"CVE-2024-12801",
			Arrays.asList("ch.qos.logback:logback-core"),
			Arrays.asList("1.2.13-rx1", "1.2.13-rx2", "1.2.13-rx3")),
	CVE202412798(
			"CVE-2024-12798",
			Arrays.asList("ch.qos.logback:logback-core", "ch.qos.logback:logback-classic"),
			Arrays.asList("1.2.13-rx1", "1.2.13-rx2", "1.2.13-rx3")),
	CVE202511226(
			"CVE-2025-11226",
			Arrays.asList("ch.qos.logback:logback-core"),
			Arrays.asList("1.2.13-rx2", "1.2.13-rx3")),
	CVE20261225(
			"CVE-2026-1225",
			Arrays.asList("ch.qos.logback:logback-core"),
			Arrays.asList("1.2.13-rx3")),
	CVE201818809(
			"CVE-2018-18809",
			Arrays.asList("net.sf.jasperreports:jasperreports"),
			Arrays.asList("6.4.0.2-Rx", "6.4.0.3-Rx")),
	CVE202510492(
			"CVE-2025-10492",
			Arrays.asList("net.sf.jasperreports:jasperreports"),
			Arrays.asList("6.4.0.3-Rx")),
	CVE202522228(
			"CVE-2025-22228", 
			Arrays.asList("org.springframework.security:spring-security-crypto"),
			Arrays.asList("5.8.16-rxlogix-1", "5.8.16-rxlogix-2")),
	CVE202622732(
			"CVE-2026-22732",
			Arrays.asList("org.springframework.security:spring-security-web"),
			Arrays.asList("5.8.16-rxlogix-2")),
	CVE202622746(
			"CVE-2026-22746",
			Arrays.asList("org.springframework.security:spring-security-core"),
			Arrays.asList("5.8.16-rxlogix-2")),
	CVE202522235(
			"CVE-2025-22235",
			Arrays.asList("org.springframework.boot:spring-boot-actuator-autoconfigure"),
			Arrays.asList("2.7.18-rxlogix-1", "2.7.18-rxlogix-2", "2.7.18-rxlogix-3", "2.7.18-rxlogix-4")),
	CVE202622733(
			"CVE-2026-22733",
			Arrays.asList(
					"org.springframework.boot:spring-boot-actuator-autoconfigure",
					"org.springframework.boot:spring-boot-actuator"),
			Arrays.asList("2.7.18-rxlogix-2", "2.7.18-rxlogix-3", "2.7.18-rxlogix-4")),
	CVE202640973(
			"CVE-2026-40973",
			Arrays.asList("org.springframework.boot:spring-boot"),
			Arrays.asList("2.7.18-rxlogix-3", "2.7.18-rxlogix-4")),
	CVE202640974(
			"CVE-2026-40974",
			Arrays.asList("org.springframework.boot:spring-boot-autoconfigure"),
			Arrays.asList("2.7.18-rxlogix-3", "2.7.18-rxlogix-4")),
	CVE202640975(
			"CVE-2026-40975",
			Arrays.asList("org.springframework.boot:spring-boot"),
			Arrays.asList("2.7.18-rxlogix-3", "2.7.18-rxlogix-4")),
	CVE202640977(
			"CVE-2026-40977",
			Arrays.asList("org.springframework.boot:spring-boot"),
			Arrays.asList("2.7.18-rxlogix-3", "2.7.18-rxlogix-4")),
	CVE202641001(
			"CVE-2026-41001",
			Arrays.asList("org.springframework.boot:spring-boot-autoconfigure"),
			Arrays.asList("2.7.18-rxlogix-4")),
	CVE202548924(
			"CVE-2025-48924", 
			Arrays.asList("commons-lang:commons-lang"),
			Arrays.asList("2.6.rx1")),
	CVE202522227(
			"CVE-2025-22227", 
			Arrays.asList("io.projectreactor.netty:reactor-netty-http"),
			Arrays.asList("1.0.39.rx1")),
	CVE202567721(
			"CVE-2025-67721",
			Arrays.asList("io.airlift:aircompressor"),
			Arrays.asList("0.27.rx.1")),
	CVE202568161(
			"CVE-2025-68161",
			Arrays.asList("org.apache.logging.log4j:log4j-core"),
			Arrays.asList("2.17.2-rxlogix-1")),
	CVE202634477(
			"CVE-2026-34477",
			Arrays.asList("org.apache.logging.log4j:log4j-core"),
			Arrays.asList("2.17.2-rxlogix-1")),
	CVE202634479(
			"CVE-2026-34479",
			Arrays.asList(
					"org.apache.logging.log4j:log4j-1.2-api",
					"org.apache.logging.log4j:log4j-core"),
			Arrays.asList("2.17.2-rxlogix-1")),
	CVE202634480(
			"CVE-2026-34480",
			Arrays.asList("org.apache.logging.log4j:log4j-core"),
			Arrays.asList("2.17.2-rxlogix-1"));
	
	private final String value;
	private final List<String> packages; 
	private final List<String> fixVersions;
	
	private CveHandled(String value, List<String> packages, List<String> fixVersions) {
		this.value = value;
		this.packages = packages;
		this.fixVersions = fixVersions;
	}
	

	public String getValue() {
		return value;
	}
	
	public List<String> getFixVersions() {
		return fixVersions;
	}
	
	public List<String> getPackages(){
		return packages;
	}
	
}
