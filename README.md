# Malicious URL Detector

A Java-based malicious URL detection system using **Bloom Filters** and **custom hash functions** for fast and efficient URL classification.

## 🚀 Features

* 🔐 Detects potentially malicious URLs
* ⚡ Uses **Bloom Filters** for fast membership checking
* 🧮 Implements custom **DJB2** and **SDBM** hash functions
* 🔗 Validates and normalizes URLs
* 🌐 Extracts and checks URL hosts/domains
* 📊 Calculates a heuristic-based risk score
* 🚦 Classifies URLs as:

  * `SAFE`
  * `SUSPICIOUS`
  * `MALICIOUS`
* 📝 Provides reasons contributing to the risk score
* ➕ Allows suspicious/high-risk URLs to be added to the malicious URL list
* 💾 Stores malicious URLs in a local text file
* 🖥️ Provides a command-line interface

---

## 🏗️ System Pipeline

```text
                 URL Input
                    │
                    ▼
            ┌───────────────┐
            │ URL Validation│
            └───────┬───────┘
                    │
                    ▼
            ┌───────────────┐
            │ URL Normalizing│
            └───────┬───────┘
                    │
              ┌─────┴─────┐
              ▼           ▼
         Full URL       Host
              │           │
              └─────┬─────┘
                    ▼
            ┌───────────────┐
            │ Bloom Filter  │
            │    Check      │
            └───────┬───────┘
                    │
                    ▼
            ┌───────────────┐
            │ Risk Scoring  │
            │ + Heuristics  │
            └───────┬───────┘
                    │
                    ▼
            ┌───────────────┐
            │ Classification│
            └───────┬───────┘
                    │
          ┌─────────┼─────────┐
          ▼         ▼         ▼
        SAFE    SUSPICIOUS  MALICIOUS
```

---

## 🧠 How It Works

### 1. Malicious URL Dataset

Known malicious URLs are stored in:

```text
malicious_urls.txt
```

The URLs are normalized before being inserted into the Bloom Filter.

Both the normalized URL and its host/domain can be checked during detection.

---

### 2. Bloom Filter

The project uses a **Bloom Filter**, a probabilistic data structure designed for efficient membership testing.

The Bloom Filter uses multiple hash functions to map URLs to positions in a bit array.

```text
                    URL
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
     Hash 1       Hash 2       Hash 3
        │            │            │
        ▼            ▼            ▼
      Bit 1        Bit 2        Bit 3
```

A Bloom Filter can determine that an element is **definitely not present** or **possibly present**.

> A positive Bloom Filter result can theoretically be a false positive.

---

## 🧮 Hash Functions

The project implements two custom hash functions:

### DJB2

```java
djb2(String str)
```

### SDBM

```java
sdbm(String str)
```

These functions are implemented in:

```text
HashFunctions.java
```

They are used to generate hash values for Bloom Filter membership checking.

---

## 🔗 URL Validation and Normalization

Before checking a URL, the system validates and normalizes it.

The normalization process handles aspects such as:

* URL schemes
* Host names
* Ports
* Paths
* Trailing slashes
* Internationalized domain names

This allows different representations of the same URL to be handled more consistently.

Example:

```text
example.com
```

can be normalized to:

```text
http://example.com/
```

---

## 📊 Risk Scoring

The system calculates a risk score from **0 to 100** using multiple URL characteristics.

Factors considered include:

* Known malicious URL
* Known malicious host/domain
* Suspicious keywords
* IP address used as the host
* Long domain names
* Long URL paths
* High subdomain depth
* Long top-level domains

### Suspicious Keywords

The system checks for keywords associated with potentially suspicious URLs, including:

```text
login
signin
verify
account
update
confirm
download
install
secure
bank
payment
credentials
token
session
auth
redirect
```

---

## 🚦 URL Classification

The calculated risk score is classified into three categories:

| Risk Score | Classification |
| ---------: | -------------- |
|     `0–39` | SAFE           |
|    `40–69` | SUSPICIOUS     |
|   `70–100` | MALICIOUS      |

The final score is limited to the range `0–100`.

---

## 📝 Detection Results

The application provides information about the detected URL, including:

* URL
* Validity
* Risk score
* Classification
* Reasons contributing to the score

Example:

```text
--- URL Check Result ---
URL: http://example.com/login
Valid: true
Risk Score: 50
Result: SUSPICIOUS

Reasons:
 - Contains suspicious keyword: 'login'
```

---

## ➕ Updating the Malicious URL List

The application can update the malicious URL dataset.

### High-Risk URLs

URLs with a risk score of `70` or higher can be added to the malicious URL list automatically.

### Suspicious URLs

For URLs classified as suspicious, the user can choose whether to add them:

```text
The URL is suspicious.
Do you want to add it to the malicious list? (yes/no):
```

When added, the URL is stored in:

```text
malicious_urls.txt
```

and included in subsequent Bloom Filter checks.

---

## 📂 Project Structure

```text
Malicious-URL-Detector/
│
├── src/
│   └── case_study/
│       ├── BloomFilters.java
│       ├── CheckResult.java
│       ├── HashFunctions.java
│       ├── Main.java
│       └── MaliciousURLChecker.java
│
├── malicious_urls.txt
├── README.md
└── .gitignore
```

---

## 🛠️ Technologies Used

| Technology       | Purpose                               |
| ---------------- | ------------------------------------- |
| Java             | Core programming language             |
| Bloom Filter     | Probabilistic URL membership checking |
| BitSet           | Bloom Filter storage                  |
| DJB2             | Custom hash function                  |
| SDBM             | Custom hash function                  |
| URI / IDN        | URL parsing and normalization         |
| Java Collections | Data management                       |

---

## ⚙️ Requirements

* **Java JDK 8 or higher**
* Java-compatible IDE or terminal
* `malicious_urls.txt`

---

## ▶️ Running the Project

### Using an IDE

Import the project into your Java IDE and run:

```text
Main.java
```

### Using the Terminal

From the project root directory:

```bash
javac -d bin src/case_study/*.java
```

Then run:

```bash
java -cp bin case_study.Main
```

---

## 💻 Usage

After starting the application:

```text
Malicious URL Checker
Type 'exit' to quit.

Enter URL to check:
```

Enter a URL:

```text
https://example.com
```

The application returns the corresponding validation result, risk score, classification, and detection reasons.

To exit:

```text
exit
```

---

## 🔍 Core Components

### `BloomFilters.java`

Handles:

* Bloom Filter initialization
* Filter size calculation
* Number of hash functions
* Adding URLs
* Membership checking
* Element counting

### `HashFunctions.java`

Contains:

* DJB2 hash function
* SDBM hash function

### `MaliciousURLChecker.java`

Handles the main URL detection logic:

* Loading malicious URLs
* URL validation
* URL normalization
* Host extraction
* Bloom Filter checking
* Risk-score calculation
* URL classification
* Detection reasons
* Updating the malicious URL list

### `CheckResult.java`

Stores the result of a URL check, including:

* Risk score
* Message
* URL
* URL validity
* Detection reasons

### `Main.java`

Provides the command-line interface for:

* Entering URLs
* Checking URLs
* Viewing detection results
* Adding suspicious URLs
* Exiting the application

---

## ⚠️ Limitations

* Detection depends on the available malicious URL dataset and heuristic rules.
* Bloom Filters may produce false-positive membership results.
* The system does not currently perform live threat-intelligence lookups.
* Risk scores are heuristic-based and should not be considered definitive security verdicts.
* The current implementation uses local file-based storage.
* The system does not use a machine-learning model for URL classification.

---

## 🔮 Future Improvements

* 🌐 Integrate threat-intelligence APIs
* 🧠 Add machine-learning-based URL classification
* 📈 Evaluate using precision, recall, F1-score, and false-positive rate
* 🔄 Automatically update the malicious URL dataset
* 🗃️ Replace file-based storage with a database
* 🌍 Develop a web-based interface
* 📊 Add detection statistics and visualization
* ⚡ Benchmark Bloom Filter performance against other data structures
* 🔍 Add more URL security heuristics

---

## 🎯 Learning Objectives

This project demonstrates practical applications of:

* Data Structures and Algorithms
* Bloom Filters
* Hash Functions
* Probabilistic Data Structures
* String Processing
* URL Parsing
* File Handling
* Object-Oriented Programming
* Heuristic-based classification

---


⭐ If you found this project interesting, feel free to explore the implementation and experiment with different URLs and Bloom Filter configurations.
