package case_study;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.regex.Pattern;

public class MaliciousURLChecker {
	 private final BloomFilters bloomFilter;
     private final String filePath;
     private final Set<String> loadedUrls = Collections.synchronizedSet(new HashSet<>());
     private static final Pattern URL_PATTERN = Pattern.compile(
             "^(https?|ftp)://[^\\s/$.?#].[^\\s]*$",
             Pattern.CASE_INSENSITIVE
     );
     private static final String[] SUSPICIOUS_KEYWORDS = new String[]{
             "login", "signin", "verify", "account", "update", "confirm", "patch",
             "download", "install", "secure", "bank", "pay", "payment",
             "credentials", "token", "session", "auth", "redirect", "signin"
     };
     
     public MaliciousURLChecker(String filePath, int expectedElements, double falsePositiveRate) {
         this.bloomFilter = new BloomFilters(expectedElements, falsePositiveRate);
         this.filePath = filePath;
         loadMaliciousURLs(filePath);
     }

     private void loadMaliciousURLs(String filePath) {
         try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
             String url;
             while ((url = br.readLine()) != null) {
                 String trimmed = url.trim();
                 if (trimmed.isEmpty()) continue;
                 String normalized = normalizeURLSafe(trimmed);
                 if (normalized == null) continue;
                 bloomFilter.add(normalized);
                 String host = extractHost(normalized);
                 if (host != null) bloomFilter.add(host);
                 loadedUrls.add(normalized);
                 loadedUrls.add(host == null ? "" : host);
             }
         } catch (IOException e) {
             if (!(e instanceof FileNotFoundException)) {
                 System.err.println("Error loading malicious URLs: " + e.getMessage());
             }
         }
     }
     
     public CheckResult isMalicious(String url) {
         if (url == null) 
        	 return new CheckResult(0, "INVALID INPUT (null)", url, false, Collections.emptyList());
         String trimmed = url.trim();
         if (trimmed.isEmpty()) 
        	 return new CheckResult(0, "INVALID INPUT (empty)", trimmed, false, Collections.emptyList());
         if (!URL_PATTERN.matcher(trimmed).matches()) {
             String tryNorm = normalizeURLSafe(trimmed);
             if (tryNorm == null) {
                 return new CheckResult(0, "INVALID URL FORMAT", trimmed, false, Collections.emptyList());
             } else {
                 trimmed = tryNorm;
             }
         }
         String normalized = normalizeURLSafe(trimmed);
         if (normalized == null) {
             return new CheckResult(0, "COULD NOT NORMALIZE URL", trimmed, false, Collections.emptyList());
         }
         
         int score = computeRiskScore(normalized);
         String label = labelFromScore(score);
         List<String> reasons = generateReasons(normalized, score);
         String message = (score >= 70 ? "MALICIOUS" : score >= 40 ? "SUSPICIOUS" : "SAFE")
                 + " (score=" + score + ", label=" + label + ")";
         
         return new CheckResult(score, message, normalized, true, reasons);
     }
     
     public void addMaliciousURL(String url) {
         String normalized = normalizeURLSafe(url);
         if (normalized == null) {
             System.err.println("Not a valid URL: " + url);
             return;
         }

         if (loadedUrls.contains(normalized)) 
        	 return;

         bloomFilter.add(normalized);
         String host = extractHost(normalized);
         
         if (host != null) 
        	 bloomFilter.add(host);
         loadedUrls.add(normalized);
         
         if (host != null) 
        	 loadedUrls.add(host);

         synchronized (this) {
             try (PrintWriter out = new PrintWriter(new FileWriter(filePath, true))) {
                 out.println(normalized);
             } catch (IOException e) {
                 System.err.println("Error saving URL to file: " + e.getMessage());
             }
         }
     }
     private String normalizeURLSafe(String raw) {
         try {
             URI uri = new URI(raw.trim());
             String scheme = uri.getScheme();
             
             if (scheme == null) {
                 uri = new URI("http://" + raw.trim());
                 scheme = uri.getScheme();
             }
             
             scheme = scheme.toLowerCase(Locale.ROOT);
             String host = uri.getHost();
             int port = uri.getPort();
             String path = uri.getRawPath();
             String query = uri.getRawQuery();

             if (host == null) {
                 String authority = uri.getRawAuthority();
                 if (authority != null) {
                     int at = authority.lastIndexOf('@');
                     host = (at >= 0) ? authority.substring(at + 1) : authority;
                     int colon = host.indexOf(':');
                     if (colon >= 0) {
                         try {
                             port = Integer.parseInt(host.substring(colon + 1));
                             host = host.substring(0, colon);
                         } catch (NumberFormatException ignored) {
                         }
                     }
                 }
             }

             if (host == null) 
            	 return null;
             host = IDN.toASCII(host.toLowerCase(Locale.ROOT));
             if ((scheme.equals("http") && port == 80) || (scheme.equals("https") && port == 443)) {
                 port = -1;
             }
             if (path == null || path.isEmpty()) 
            	 path = "/";
             else 
            	 path = new URI(path).normalize().getPath();
             if (path.length() > 1 && path.endsWith("/")) 
            	 path = path.substring(0, path.length() - 1);
             StringBuilder sb = new StringBuilder();
             sb.append(scheme).append("://").append(host);
             if (port != -1) 
            	 sb.append(":").append(port);
             sb.append(path);
             if (query != null && !query.isEmpty()) 
            	 sb.append("?").append(query);
             return sb.toString();
         } catch (Exception e) {
             return null;
         }
     }
     
     private String extractHost(String normalizedUrl) {
         try {
             URI uri = new URI(normalizedUrl);
             return uri.getHost();
         } catch (URISyntaxException e) {
             return null;
         }
     }
     
     private int computeRiskScore(String normalizedUrl) {
         int score = 0;
         String host = extractHost(normalizedUrl);
         String lower = normalizedUrl.toLowerCase(Locale.ROOT);

         if (bloomFilter.contains(normalizedUrl)) 
        	 score += 80;
         if (host != null && bloomFilter.contains(host)) 
        	 score += 60;
         int keywordCount = 0;
         for (String kw : SUSPICIOUS_KEYWORDS)
             if (lower.contains(kw)) 
            	 keywordCount++;
         score += Math.min(80, keywordCount * 25);

         if (host != null && host.matches("^(\\d{1,3}\\.){3}\\d{1,3}$")) 
        	 score += 20;
         int domainLength = (host == null ? 0 : host.length());
         int pathLength = normalizedUrl.length() - (host == null ? 0 : normalizedUrl.indexOf(host) + host.length());
         if (domainLength > 30) 
        	 score += 5;
         if (pathLength > 80) 
        	 score += 5;

         if (host != null) {
             int dots = host.length() - host.replace(".", "").length();
             if (dots >= 3) 
            	 score += 5;
             int lastDot = host.lastIndexOf('.');
             if (lastDot != -1 && host.length() - lastDot - 1 > 3) 
            	 score += 3;
         }

         if (keywordCount >= 2 && score < 70) 
        	 score = 75;

         return Math.min(Math.max(score, 0), 100);
     }
     
     private String labelFromScore(int score) {
         if (score >= 70) 
        	 return "MALICIOUS";
         if (score >= 40) 
        	 return "SUSPICIOUS";
         return "SAFE";
     }
     
     private List<String> generateReasons(String normalizedUrl, int score) {
         List<String> reasons = new ArrayList<>();
         
         if (bloomFilter.contains(normalizedUrl))
             reasons.add("Exact URL found in blocklist.");
         
         String host = extractHost(normalizedUrl);
         
         if (host != null && bloomFilter.contains(host))
             reasons.add("Domain/host found in blocklist.");
         
         String lower = normalizedUrl.toLowerCase(Locale.ROOT);
         
         for (String kw : SUSPICIOUS_KEYWORDS)
             if (lower.contains(kw)) 
            	 reasons.add("Contains suspicious keyword: '" + kw + "'");
         
         if (host != null && host.matches("^(\\d{1,3}\\.){3}\\d{1,3}$")) 
        	 reasons.add("Host is an IP address.");
         
         if (score >= 70 && reasons.isEmpty()) 
        	 reasons.add("High score by heuristics.");
         
         return reasons;
     }
     
     
     


}
