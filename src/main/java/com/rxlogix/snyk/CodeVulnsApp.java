package com.rxlogix.snyk;

import java.io.File;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.FileUtils;

public class CodeVulnsApp {

	public static void main(String[] args) throws Exception{
		String filePath = "/home/lt-deepakagrawal1/sss.txt";

		File file = new File(filePath);

		String fileText = FileUtils.readFileToString(file);
		fileText = fileText.substring(fileText.indexOf("ScanIssue("), fileText.length());
		 // Check if there are newlines at all
        //System.out.println("DEBUG: Does text contain newline? " + fileText.contains("\n"));
		int issueCount = 0;
        // Split based on ScanIssue(
        for (String scanIssue : fileText.split("(?=ScanIssue\\()")) {
            //System.out.println(scanIssue);  // This should print with newlines if they exist

            Matcher titleMatcher = Pattern.compile("title=([^,]+)").matcher(scanIssue);
            String title = titleMatcher.find() ? titleMatcher.group(1).trim() : "N/A";

            Matcher severityMatcher = Pattern.compile("severity=([^,\\s]+)").matcher(scanIssue);
            String severity = severityMatcher.find() ? severityMatcher.group(1).trim() : "N/A";


            Matcher cveMatcher = Pattern.compile("cwe=\\[([^\\]]+)\\]").matcher(scanIssue);
            String cve = cveMatcher.find() ? cveMatcher.group(1).trim() : "N/A";

            Matcher packageMatcher = Pattern.compile("filePath=([^,\\s]+)").matcher(scanIssue);
            String packageName = packageMatcher.find() ? packageMatcher.group(1) : "N/A";

            Matcher versionMatcher = Pattern.compile("start\\s*=\\s*Position\\s*\\[\\s*line\\s*=\\s*(\\d+)").matcher(scanIssue);
            String version = versionMatcher.find() ? versionMatcher.group(1) : "N/A";


            if(Arrays.stream(CveHandled.values()).noneMatch(c -> c.getValue().equalsIgnoreCase(cve)
            		&& c.getFixVersions().stream().anyMatch(a->a.equalsIgnoreCase(version))
            		&& c.getPackages().stream().anyMatch(p->p.equalsIgnoreCase(packageName)))) {
            	System.out.println("----- SCAN ISSUE ("+ (++issueCount) +")-----");
            	System.out.println("filePath: " + (packageName != null ? packageName : "Not found"));
                System.out.println("Line     : " + (version != null ? version : "Not found"));

                System.out.println("Title   : " + title);
                System.out.println("Severity: " + severity);
                System.out.println("CVE     : " + cve);

                System.out.println();
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

	}
}
