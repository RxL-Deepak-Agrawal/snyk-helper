package com.rxlogix.snyk;

import java.util.HashMap;
import java.util.Map;

public class Test {

	public static void main(String[] args) {
		Map<String, Map<String, Map<String, Map<String, String>>>> map = new HashMap<>();
		
		map.computeIfAbsent("ram", k -> new HashMap<>()).computeIfAbsent("shyam", k -> new HashMap<>());
		
		System.out.println(map.get("ram"));
			
	}
	
}
