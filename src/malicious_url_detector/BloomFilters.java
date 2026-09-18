package case_study;

import java.util.*;

public class BloomFilters {
	private final BitSet bitset;
    private final int size;
    private final int[] seeds;
    private int elementCount;
    
    public BloomFilters(int expectedElements, double falsePositiveRate) {
        this.size = calculateOptimalSize(expectedElements, falsePositiveRate);
        this.seeds = generateSeeds(calculateOptimalHashFunctions(size, expectedElements));
        this.bitset = new BitSet(size);
        this.elementCount = 0;
    }
    
    private int calculateOptimalSize(int n, double p) {
        return (int) Math.ceil(-(n * Math.log(p)) / (Math.log(2) * Math.log(2)));
    }
    
    private int calculateOptimalHashFunctions(int m, int n) {
        return Math.max(1, (int) Math.round((double) m / n * Math.log(2)));
    }
    
    private int[] generateSeeds(int k) {
        int[] seeds = new int[k];
        for (int i = 0; i < k; i++) {
            seeds[i] = 31 + i * 17;
        }
        return seeds;
    }
    
    private int hash(String data, int seed) {
        int hash = seed;
        for (char c : data.toCharArray()) {
            hash = (hash * 31 + c) & 0x7fffffff;
        }
        return Math.abs(hash % size);
    }
    
    public void add(String data) {
        for (int seed : seeds) {
            bitset.set(hash(data, seed));
        }
        elementCount++;
    }
    
    public boolean contains(String data) {
        for (int seed : seeds) {
            if (!bitset.get(hash(data, seed))) {
                return false;
            }
        }
        return true;
    }
    
    public int getElementCount() {
        return elementCount;
    }
    
}
