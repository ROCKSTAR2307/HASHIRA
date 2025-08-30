package com_security;

import java.io.*;
import java.math.BigInteger;
import java.util.*;

public class SecretReconstructor {

    // Simple holder for (x, y)
    static class Share {
        int x;
        BigInteger y;
        Share(int x, BigInteger y) { this.x = x; this.y = y; }
    }

    // absolute BigInteger
    private static BigInteger abs(BigInteger a) { return a.signum() < 0 ? a.negate() : a; }

    // Add two fractions: a/b + c/d -> returns reduced {num, den}
    private static BigInteger[] addFractions(BigInteger a, BigInteger b, BigInteger c, BigInteger d) {
        BigInteger newNum = a.multiply(d).add(c.multiply(b));
        BigInteger newDen = b.multiply(d);
        BigInteger g = abs(newNum).gcd(abs(newDen));
        if (!g.equals(BigInteger.ZERO)) {
            newNum = newNum.divide(g);
            newDen = newDen.divide(g);
        }
        return new BigInteger[]{newNum, newDen};
    }

    // Lagrange interpolation at x=0 computed exactly as a rational sum.
    // Throws if result isn't integer (subset invalid).
    public static BigInteger lagrangeAtZeroExact(List<Share> shares) throws ArithmeticException {
        int k = shares.size();
        BigInteger totalNum = BigInteger.ZERO;
        BigInteger totalDen = BigInteger.ONE;

        for (int i = 0; i < k; i++) {
            BigInteger xi = BigInteger.valueOf(shares.get(i).x);
            BigInteger yi = shares.get(i).y;

            BigInteger num = BigInteger.ONE; // product of (0 - xj) = product(-xj)
            BigInteger den = BigInteger.ONE; // product of (xi - xj)
            for (int j = 0; j < k; j++) {
                if (i == j) continue;
                BigInteger xj = BigInteger.valueOf(shares.get(j).x);
                num = num.multiply(xj.negate());
                den = den.multiply(xi.subtract(xj));
            }

            BigInteger termNum = yi.multiply(num);
            BigInteger termDen = den;

            BigInteger[] res = addFractions(totalNum, totalDen, termNum, termDen);
            totalNum = res[0];
            totalDen = res[1];
        }

        BigInteger[] divRem = totalNum.divideAndRemainder(totalDen);
        if (!divRem[1].equals(BigInteger.ZERO)) {
            throw new ArithmeticException("Non-integer interpolation result");
        }
        return divRem[0];
    }

    // Generate all combinations of indices and record which subset produced which secret.
    // secretToSubsets: secret -> list of subsets (each subset is list of indices)
    private static void combinationsCollect(int start, List<Integer> current, int k,
                                            List<Share> shares, Map<BigInteger, List<List<Integer>>> secretToSubsets) {
        if (current.size() == k) {
            List<Share> subset = new ArrayList<>();
            for (int idx : current) subset.add(shares.get(idx));
            try {
                BigInteger secret = lagrangeAtZeroExact(subset);
                secretToSubsets.computeIfAbsent(secret, s -> new ArrayList<>()).add(new ArrayList<>(current));
            } catch (Exception e) {
                // invalid subset - ignore
            }
            return;
        }
        for (int i = start; i < shares.size(); i++) {
            current.add(i);
            combinationsCollect(i + 1, current, k, shares, secretToSubsets);
            current.remove(current.size() - 1);
        }
    }

    // Robust simple parser for the specific JSON format.
    public static List<Share> parseInputFile(String filePath, int[] outNk) throws IOException {
        List<Share> shares = new ArrayList<>();
        int n = 0, k = 0;

        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.contains("\"n\"")) {
                    String s = line.split(":")[1].replaceAll("[^0-9]", "");
                    if (!s.isEmpty()) n = Integer.parseInt(s);
                } else if (line.contains("\"k\"")) {
                    String s = line.split(":")[1].replaceAll("[^0-9]", "");
                    if (!s.isEmpty()) k = Integer.parseInt(s);
                } else if (line.matches("\"[0-9]+\"\\s*:\\s*\\{.*")) {
                    int x = Integer.parseInt(line.split(":")[0].replaceAll("[^0-9]", ""));
                    String baseLine = br.readLine();
                    if (baseLine == null) break;
                    baseLine = baseLine.trim();
                    String valueLine = br.readLine();
                    if (valueLine == null) break;
                    valueLine = valueLine.trim();

                    String baseStr = baseLine.split(":")[1].replaceAll("[^0-9]", "");
                    String valStr = valueLine.split(":")[1].trim();
                    valStr = valStr.replaceAll("^\"|\"[,\\s]*$|,$", "");
                    valStr = valStr.replaceAll("[^0-9A-Za-z]+", "");

                    int base = Integer.parseInt(baseStr);
                    BigInteger y = new BigInteger(valStr, base);
                    shares.add(new Share(x, y));
                }
            }
        }
        outNk[0] = n; outNk[1] = k;
        return shares;
    }

    // -------------------- main --------------------
    public static void main(String[] args) {
        String filePath = "input.json"; // project root
        try {
            int[] outNk = new int[2];
            List<Share> shares = parseInputFile(filePath, outNk);
            int n = outNk[0], k = outNk[1];

            if (shares.size() == 0 || k <= 0) {
                System.err.println("No shares parsed or invalid k.");
                return;
            }

            // collect secret -> list of subsets producing it
            Map<BigInteger, List<List<Integer>>> secretToSubsets = new HashMap<>();
            combinationsCollect(0, new ArrayList<>(), k, shares, secretToSubsets);

            if (secretToSubsets.isEmpty()) {
                System.err.println("No valid subset produced an integer secret.");
                return;
            }

            // Find the winning secret (most subsets)
            BigInteger winningSecret = null;
            int bestCount = -1;
            for (Map.Entry<BigInteger, List<List<Integer>>> e : secretToSubsets.entrySet()) {
                int cnt = e.getValue().size();
                // choose secret with max count; tie-breaker arbitrary
                if (cnt > bestCount) { bestCount = cnt; winningSecret = e.getKey(); }
            }

            List<List<Integer>> winningSubsets = secretToSubsets.get(winningSecret);
            int totalWinning = winningSubsets.size();

            // For each share index, count how many winning subsets include it
            int m = shares.size();
            int[] includeCount = new int[m];
            for (List<Integer> subset : winningSubsets) {
                for (int idx : subset) includeCount[idx]++;
            }

            // Build suspected list: those with 0 inclusion
            List<Integer> definitelyBad = new ArrayList<>();
            List<Integer> suspicious = new ArrayList<>();
            for (int i = 0; i < m; i++) {
                if (includeCount[i] == 0) definitelyBad.add(i);
                else {
                    // if appears in less than half the winning subsets, flag as suspicious
                    if (includeCount[i] * 2 < totalWinning) suspicious.add(i);
                }
            }

            // Output results
            System.out.println("Secret: " + winningSecret.toString());
            System.out.println(); 

            System.out.println("Winning-subset-count for secret = " + totalWinning);
            System.out.println();

            // Print each share's inclusion stats
            System.out.println("Share inclusion in winning subsets:");
            for (int i = 0; i < m; i++) {
                Share s = shares.get(i);
                System.out.printf("  index %d (x=%d) included in %d/%d winning subsets%n",
                                  i, s.x, includeCount[i], totalWinning);
            }
            System.out.println();

            if (definitelyBad.isEmpty() && suspicious.isEmpty()) {
                System.out.println("No wrong shares detected (all shares appear frequently in winning subsets).");
            } else {
                if (!definitelyBad.isEmpty()) {
                    System.out.println("Highly suspicious (likely wrong) share indices:");
                    for (int idx : definitelyBad) {
                        Share s = shares.get(idx);
                        System.out.printf("  index %d -> x=%d, y=%s%n", idx, s.x, s.y.toString());
                    }
                }
                if (!suspicious.isEmpty()) {
                    System.out.println("Possibly suspicious shares (appear in fewer than half the winning subsets):");
                    for (int idx : suspicious) {
                        Share s = shares.get(idx);
                        System.out.printf("  index %d -> x=%d, y=%s (included %d/%d)%n",
                                          idx, s.x, s.y.toString(), includeCount[idx], totalWinning);
                    }
                }
            }

        } catch (FileNotFoundException fnf) {
            System.err.println("File not found: " + filePath + " — put input.json at project root.");
        } catch (IOException ioe) {
            System.err.println("IO error: " + ioe.getMessage());
        } catch (Exception e) {
            System.err.println("Unexpected error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
