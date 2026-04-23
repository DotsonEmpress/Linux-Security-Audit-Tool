# Linux Security & Network Audit Tool 🛡️
**Developed by Dotson Mbanwei *BTECH IT Candidate - Level 2 | System Administration*

---

## 🚀 Overview
This is a modular Python-based utility designed to automate system security hardening and network vulnerability assessments. Instead of running multiple separate commands, this tool centralizes security checks into one interface.

## 🛠️ Key Features
- **Network Audit**: Uses `nmap` to identify open ports, active services, and potential entry points.
- **Compliance Module**: Checks system configurations against hardening standards (CIS Benchmarks).
- **Modular Architecture**: Built with a clean separation between the core manager (`audit.py`) and specialized scanning logic in the `modules/` folder.
- **Reporting**: Generates structured audit summaries for system administrators.

## 📁 Project Structure
```text
audit_tool/
├── audit.py              # Main entry point (The Manager)
├── modules/              # Specialist logic folder
│   ├── network_audit.py    # Nmap integration
│   └── compliance_audit.py # System hardening checks
└── README.md             # Project documentation

## Execute a Network Scan
\\\ sudo python3 audit.py --network

You write those sections **inside the README.md file** itself. 

In the IT world, the `README.md` is like the "Cover Page" of your project. When you write it using the `nano` command we used earlier, GitHub automatically reads that file and displays it beautifully on your repository’s main page.

### 1. Where to put it in the file
You should place the **How to Run** and **Tech Stack** sections toward the bottom of the file, after you have explained what the project does. This follows the standard professional format:
1.  **Title** (What is this?)
2.  **Features** (What can it do?)
3.  **Structure** (How is it organized?)
4.  **How to Run** (How do I use it?)
5.  **Tech Stack** (What tools did I use?)

---

### 2. How to write it (The Syntax)
Since it is a `.md` (Markdown) file, you use special symbols to make it look professional:
* Use `##` for **Headings**.
* Use triple backticks ( ``` ) to create **Code Blocks** (this makes the commands look like they are in a terminal).

**Here is exactly how those sections should look inside your `nano` editor:**

```markdown
## 💻 How to Run
To use this tool, follow these steps in your Ubuntu terminal:

1. **Install Dependencies**:
   ```bash
   sudo apt update && sudo apt install nmap
   pip install python-nmap
   ```

2. **Execute a Network Scan**:
   ```bash
   sudo python3 audit.py --network
   ```

## 🧪 Tech Stack
This project was built using:
* **Language**: Python 3.10+
* **Security Tools**: Nmap (Network Mapper)
* **OS Environment**: Ubuntu Linux 22.04 LTS
* **Version Control**: Git & GitHub
```



---

### 3. Step-by-Step to Update It
If you have already created the file and want to add these parts now:

1.  **Open the file again:**
    ```bash
    nano ~/audit_tool/README.md
    ```
2.  **Scroll to the bottom** using your arrow keys.
3.  **Type or paste** the sections above.
4.  **Save and Exit:** Press `Ctrl + O`, then `Enter`, then `Ctrl + X`.
5.  **Push the changes to GitHub:**
    ```bash
    git add README.md
    git commit -m "docs: updated README with usage instructions and tech stack"
    git push
    ```
