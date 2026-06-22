package com.rxlogix.snyk;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.io.FileUtils;

public class Application {

	private static final String GREEN = "\u001B[32m";
	private static final String RESET = "\u001B[0m";

	public static void main(String[] args) throws Exception{
        String filePath = System.getProperty("user.home") + File.separator + "sss.txt";

        File file = new File(filePath);

		String fileText = FileUtils.readFileToString(file);
		fileText = fileText.substring(fileText.indexOf("ScanIssue("), fileText.length());
		Set<String> consumedCves = new HashSet<>();

		// Group the unfixed findings: package group -> library (package@version) -> findings.
		Map<String, Map<String, List<String>>> findingsByGroup = new LinkedHashMap<>();
        // Split based on ScanIssue(
        for (String scanIssue : fileText.split("(?=ScanIssue\\()")) {
            //System.out.println(scanIssue);  // This should print with newlines if they exist

            Matcher titleMatcher = Pattern.compile("title=([^,]+)").matcher(scanIssue);
            String title = titleMatcher.find() ? titleMatcher.group(1).trim() : "N/A";

            Matcher severityMatcher = Pattern.compile("severity=([^,\\s]+)").matcher(scanIssue);
            String severity = severityMatcher.find() ? severityMatcher.group(1).trim() : "N/A";


            Matcher cveMatcher = Pattern.compile("CVE=\\[([^\\]]+)\\]").matcher(scanIssue);
            String cve = cveMatcher.find() ? cveMatcher.group(1).trim() : "N/A";

            Matcher packageMatcher = Pattern.compile("packageName=([^,\\s]+)").matcher(scanIssue);
            String packageName = packageMatcher.find() ? packageMatcher.group(1) : "N/A";

            Matcher versionMatcher = Pattern.compile("version=([^,\\s]+)").matcher(scanIssue);
            String version = versionMatcher.find() ? versionMatcher.group(1) : "N/A";

            Matcher fixedInMatcher = Pattern.compile("fixedIn=\\[([^\\]]*)\\]").matcher(scanIssue);
            String fixedIn = fixedInMatcher.find() ? fixedInMatcher.group(1).trim() : "";

            Matcher cvssMatcher = Pattern.compile("cvssScore=([^,\\s]+)").matcher(scanIssue);
            String cvssScore = cvssMatcher.find() ? cvssMatcher.group(1).trim() : "";

            // The Snyk vuln id (ruleId) gives the canonical advisory URL, which carries the
            // fix commit, references and exact fixed versions.
            Matcher ruleIdMatcher = Pattern.compile("ruleId=([^,\\s]+)").matcher(scanIssue);
            String snykUrl = ruleIdMatcher.find() ? "https://security.snyk.io/vuln/" + ruleIdMatcher.group(1).trim() : "";


            if(Arrays.stream(CveHandled.values()).noneMatch(c -> c.getValue().equalsIgnoreCase(cve)
            		&& c.getFixVersions().stream().anyMatch(a->a.equalsIgnoreCase(version))
            		&& c.getPackages().stream().anyMatch(p->p.equalsIgnoreCase(packageName)))
            		&& !consumedCves.contains(cve.toLowerCase() + "-" + packageName.toLowerCase())) {
            	if(!cve.equalsIgnoreCase("N/A")) {
            		consumedCves.add(cve.toLowerCase() + "-" + packageName.toLowerCase());
            	}

            	// A fix is available in our custom (rxlogix-patched) libs if CveHandled has an entry
            	// for this CVE + package — i.e. a patched version exists, this build just hasn't bumped to it.
            	String customFixVersions = Arrays.stream(CveHandled.values())
            			.filter(c -> c.getValue().equalsIgnoreCase(cve)
            					&& c.getPackages().stream().anyMatch(p -> p.equalsIgnoreCase(packageName)))
            			.flatMap(c -> c.getFixVersions().stream())
            			.distinct()
            			.collect(Collectors.joining(", "));
            	boolean customFixAvailable = !customFixVersions.isEmpty();

            	StringBuilder finding = new StringBuilder();
            	finding.append("  Title   : ").append(title).append("\n");
            	finding.append("  Severity: ").append(severity).append("\n");
            	finding.append("  CVE     : ").append(cve);
            	if(!cvssScore.isEmpty()) {
            		finding.append("\n  CVSS    : ").append(cvssScore);
            	}
            	if(!fixedIn.isEmpty()) {
            		finding.append("\n  Fixed In: ").append(fixedIn);
            	}
            	if(customFixAvailable) {
            		finding.append("\n  Custom Fix: ").append(customFixVersions).append(" (rxlogix)");
            	}
            	if(!snykUrl.isEmpty()) {
            		finding.append("\n  Snyk    : ").append(snykUrl);
            	}

            	// Highlight in green when a fix is available in our custom libs.
            	String findingText = customFixAvailable ? GREEN + finding + RESET : finding.toString();

            	// Package group is the Maven group id (part before ':'); library key is package@version.
            	String packageGroup = packageName.contains(":") ? packageName.substring(0, packageName.indexOf(":")) : packageName;
            	String libraryKey = packageName + "@" + version;
            	findingsByGroup.computeIfAbsent(packageGroup, k -> new LinkedHashMap<>())
            			.computeIfAbsent(libraryKey, k -> new ArrayList<>())
            			.add(findingText);
            }
            else {
//            	System.out.println("ignor" + (++ignoreCount) + " already exits: " + (consumedCves.contains(cve.toLowerCase() + "-" + packageName.toLowerCase())));
//
//            	System.out.println("Package Name: " + (packageName != null ? packageName : "Not found"));
//                System.out.println("Version     : " + (version != null ? version : "Not found"));
//
//                System.out.println("Title   : " + title);
//                System.out.println("Severity: " + severity);
//                System.out.println("CVE     : " + cve);

            }

            //break;
        }

        // Print the findings grouped by package group, then by library.
        int totalFindings = 0;
        int totalLibraries = 0;
        for (Map.Entry<String, Map<String, List<String>>> groupEntry : findingsByGroup.entrySet()) {
        	Map<String, List<String>> libraries = groupEntry.getValue();
        	int groupFindings = libraries.values().stream().mapToInt(List::size).sum();
        	totalLibraries += libraries.size();
        	System.out.println("################ " + groupEntry.getKey()
        			+ " (" + libraries.size() + " librarie(s), " + groupFindings + " finding(s)) ################");
        	for (Map.Entry<String, List<String>> libEntry : libraries.entrySet()) {
        		List<String> findings = libEntry.getValue();
        		totalFindings += findings.size();
        		System.out.println("========== " + libEntry.getKey() + " (" + findings.size() + " finding(s)) ==========");
        		int idx = 0;
        		for (String finding : findings) {
        			System.out.println("----- SCAN ISSUE (" + (++idx) + ") -----");
        			System.out.println(finding);
        			System.out.println();
        		}
        	}
        }

        System.out.println("===================================================");
        System.out.println("Total: " + totalFindings + " unfixed finding(s) across "
        		+ totalLibraries + " librarie(s) in " + findingsByGroup.size() + " package group(s)");
	}
}
