package case_study;

import java.util.*;

public class Main {
	public static void main(String[] args) {
		
		Scanner sc = new Scanner(System.in);
        String filePath = "/DSA_CASE_STUDY/src/case_study/malicious_urls.txt";
        int expectedElements = 1000;
        double falsePositiveRate = 0.01;
        MaliciousURLChecker checker = new MaliciousURLChecker(filePath, expectedElements, falsePositiveRate);

        System.out.println("Malicious URL Checker");
        System.out.println("Type 'exit' to quit.");
        
        while(true){
        	System.out.print("\nEnter URL to check: ");
            String input = sc.nextLine().trim();

            if (input.equalsIgnoreCase("exit")) 
            	break;
            if (input.isEmpty()) 
            	continue;
            
            CheckResult result = checker.isMalicious(input);
            
            System.out.println("\n--- URL Check Result ---");
            System.out.println("URL: " + result.url);
            System.out.println("Valid: " + result.isValidURL);
            System.out.println("Risk Score: " + result.riskScore);
            System.out.println("Result: " + result.message);

            if (!result.reasons.isEmpty()) {
                System.out.println("Reasons:");
                for (String reason : result.reasons) {
                    System.out.println(" - " + reason);
                }
            }
            if (result.isValidURL && result.riskScore >= 70) {
                checker.addMaliciousURL(result.url);
                System.out.println("\nThe URL has been added to the malicious list.");
            } 
            else if (result.isValidURL && result.riskScore >= 40) {
                System.out.print("\nThe URL is suspicious. Do you want to add it to the malicious list? (yes/no): ");
                String choice = sc.nextLine().trim();
                if (choice.equalsIgnoreCase("yes")) {
                    checker.addMaliciousURL(result.url);
                    System.out.println("The URL has been added to the malicious list.");
                }else {
                    System.out.println("The URL was not added.");
                }
            }
            else {
                System.out.println("\nThe URL is safe and not added to the malicious list.");
            }
        }
        sc.close();
        System.out.println("\nProgram terminated.");      
	}
}
