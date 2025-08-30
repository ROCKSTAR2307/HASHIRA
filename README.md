# Shamir's Secret Sharing - Secret Reconstruction

## 📖 Problem Statement
This assignment is based on **Shamir’s Secret Sharing (SSS)**.  
We are given a set of shares of a secret in JSON format. Each share is a point `(x, y)` on a hidden polynomial of degree `k-1`.  

- `n` = total number of shares provided.  
- `k` = minimum number of shares required to reconstruct the polynomial.  
- Each share value may be given in different bases (binary, octal, hex, etc).  
- The secret is the **constant term `c`** of the polynomial.  

Some shares may be **corrupted (wrong)**. The program must:
1. Parse shares from JSON.  
2. Convert values to decimal (`BigInteger` safe).  
3. Use **Lagrange interpolation** on all `k`-sized subsets.  
4. Find the secret `c` by majority vote.  
5. Detect and report wrong/suspicious shares.  

---

## 🚀 Features
- **Pure Java** (no external JSON libraries).  
- Handles **very large numbers** (20–40 digits) via `BigInteger`.  
- Detects **corrupted shares** using subset analysis.  
- Prints only the **secret** for submission, and optionally logs suspicious shares.  

---

## 🧩 Example Input

`input.json`:
```json
{
    "keys": { "n": 4, "k": 3 },
    "1": { "base": "10", "value": "4" },
    "2": { "base": "2", "value": "111" },
    "3": { "base": "10", "value": "12" },
    "6": { "base": "4", "value": "213" }
}
