# SCA Vulnerability Scanner

A comprehensive Software Composition Analysis (SCA) and Static Application Security Testing (SAST) tool. This project provides both a command-line interface and a modern web application to identify security vulnerabilities in your code and dependencies.

![SCA Scanner](https://via.placeholder.com/800x400?text=SCA+Vulnerability+Scanner+Dashboard)

## 🚀 Features

*   **Dependency Scanning (SCA)**:
    *   Detects vulnerabilities in `requirements.txt` (Python), `package.json` (Node.js), `pom.xml` (Java/Maven), and `Dockerfile`.
    *   Queries **OSV.dev** and **NVD** (via `nvdlib`) for up-to-date vulnerability data (CVEs).
    *   Calculates risk scores based on vulnerability severity, license risk, and deprecation status.
*   **Static Analysis (SAST)**:
    *   Scans source code for dangerous patterns (e.g., hardcoded secrets, `eval()` usage, weak authentication).
    *   Customizable rule set.
*   **Web Application**:
    *   **Frontend**: Built with **Next.js 14**, TypeScript, and Tailwind CSS for a responsive, dark-mode UI.
    *   **Backend**: **Flask** API handling file uploads, GitHub cloning, and scanning logic.
    *   **GitHub Integration**: Scan public repositories directly via URL.
    *   **Visual Reports**: Interactive dashboards showing dependency risks and code vulnerabilities.
*   **CLI Tool**: Standalone Python script for CI/CD integration or quick local scans.

## 🛠️ Tech Stack

*   **Backend**: Python 3.10+, Flask, nvdlib, GitPython
*   **Frontend**: Next.js 14, React, Tailwind CSS, Lucide Icons
*   **Data Sources**: OSV API, National Vulnerability Database (NVD)

## 📋 Prerequisites

*   Python 3.8+
*   Node.js 18+ (for Web App)
*   Git

## 📦 Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/arthuraut/sca.git
cd sca
```

### 2. Backend Setup
Create a virtual environment and install Python dependencies:

```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt
```

### 3. Frontend Setup
Install Node.js dependencies:

```bash
cd frontend
npm install
```

## 🚀 Usage

### Running the Web Application

1.  **Start the Backend API**:
    ```bash
    # From the root directory (ensure venv is active)
    python backend/app.py
    ```
    The server will start at `http://localhost:5000`.

2.  **Start the Frontend**:
    ```bash
    # In a new terminal, from the frontend/ directory
    npm run dev
    ```
    The application will be available at `http://localhost:3000`.

3.  **Use the App**:
    *   Open your browser to `http://localhost:3000`.
    *   **Upload Tab**: Drag and drop your `package.json` or `requirements.txt`.
    *   **GitHub Tab**: Paste a public GitHub repository URL (e.g., `https://github.com/octocat/Hello-World`) to scan it remotely.

### Running the CLI Tool

You can run the standalone script without the web server:

```bash
# Scan the current directory
python sca_tool.py
```

This will generate:
*   Console output with a summary.
*   `sca_report.json`: Detailed JSON report.
*   `remediation_plan.json`: Suggested fixes.

## 🛡️ Security Note

*   This tool is for educational and defensive purposes.
*   The NVD query uses `nvdlib`. Without an API key, rate limits may apply.
*   The GitHub scanner clones repositories to a temporary directory which is deleted after scanning.

## 📄 License

[MIT License](LICENSE)
