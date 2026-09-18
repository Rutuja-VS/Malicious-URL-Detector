package case_study;

import java.util.*;

public class CheckResult {
	public final int riskScore;
    public final String message;
    public final String url;
    public final boolean isValidURL;
    public final List<String> reasons;

    public CheckResult(int riskScore, String message, String url, boolean isValidURL, List<String> reasons) {
        this.riskScore = riskScore;
        this.message = message;
        this.url = url;
        this.isValidURL = isValidURL;
        this.reasons = reasons;
    }

}
