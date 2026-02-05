# DNSProbe

![Banner](logo.png)
![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![Network](https://img.shields.io/badge/Network-Tool-green.svg)

**DNSProbe** is a comprehensive DNS auditing tool designed for security professionals and network administrators. It performs deep queries across multiple record types to provide a complete picture of a domain's DNS configuration.

---

## 🚀 Features

- **📡 Multi-Record Analysis**: Queries A, AAAA, MX, TXT, NS, CNAME, and SOA records.
- **🎨 Rich Interface**: Beautiful, color-coded terminal output using the `Rich` library.
- **⚡ Fast & Async-Ready**: Optimized for quick diagnostics.
- **🛡️ Status Detection**: intelligent detection of dead or misconfigured domains.

---

## 🛠️ Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/MIHx0/DNSProbe.git
    cd DNSProbe
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

---

## 💻 Usage

Run the tool by pointing it to a domain:

```bash
python dnsprobe.py <domain>
```

**Options:**

- `-h, --help`: Show help message and exit.

**Example:**

```bash
python dnsprobe.py google.com
```

---

## 👨‍💻 Credits

<p align="center">
  <b>Built By:</b> MIHx0 (Muhammad Izaz Haider)<br>
  <b>Powered by:</b> The PenTrix
</p>

---

*Disclaimer: This tool is for educational and network diagnostic purposes only.*
