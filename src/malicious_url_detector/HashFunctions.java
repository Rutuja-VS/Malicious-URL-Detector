package case_study;

public class HashFunctions {
	
	public static int djb2(String str) {
        int hash = 5381;
        for (char c : str.toCharArray()) {
            hash = ((hash << 5) + hash) + c;
        }
        return hash & 0x7fffffff;
    }
	
	public static int sdbm(String str) {
        int hash = 0;
        for (char c : str.toCharArray()) {
            hash = c + (hash << 6) + (hash << 16) - hash;
        }
        return hash & 0x7fffffff;
    }
	
}
