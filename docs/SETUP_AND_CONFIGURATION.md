# TILI v0.2 — Installation and User Guide

**Application version:** 0.2.0  
**Purpose:** Install and run TILI locally on an individual workstation.

## 1. What you need

- Windows 10/11, Debian/Ubuntu Linux, or macOS
- Python 3.10 or newer
- 4 GB RAM minimum; 8 GB recommended for larger log sets
- Internet access for the first installation only, to download Python packages
- Around 1 GB free disk space, plus space for your log files

TILI runs locally in your browser. Uploaded logs are processed by the local application; this build does not send logs to an external AI service.

## 2. Get the project

1. Copy the `TILI v0.2` ZIP package to your workstation.
2. Extract it to a folder you can write to.
3. Open a terminal in the extracted `TILI` project folder (the folder containing `app.py`).

Do not run the application from inside the ZIP file.

## 3. Install and start on Windows

Open PowerShell in the project folder and run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

If PowerShell blocks environment activation, run:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

## 4. Install and start on Linux / macOS

Open a terminal in the project folder and run:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

On Debian/Ubuntu, if Python virtual-environment support is missing:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
```

## 5. Open TILI

After starting the application, open the local address shown in the terminal. Usually:

`http://localhost:8501`

Keep the terminal open while using TILI. Press `Ctrl+C` in the terminal to stop it.

Next time, installation is not required again. Open a terminal in the project folder, activate `.venv`, and run:

- Windows: `.\.venv\Scripts\Activate.ps1` then `python -m streamlit run app.py`
- Linux/macOS: `source .venv/bin/activate` then `python -m streamlit run app.py`

## 6. Upload logs

Supported file types:

- `.log`
- `.txt`
- `.csv`
- `.json`
- `.zip`

You can select multiple files. ZIP files are read in memory; TILI does not extract them to a folder.

**Current configured limits (v0.2.0):**

| Setting | Value |
|---|---:|
| Maximum size per uploaded file | 1024 MB |
| Maximum non-directory members in one ZIP | 1024 |
| Maximum size of an individual supported ZIP member | 1024 MB |\n| Maximum combined uncompressed supported ZIP content | 1024 MB |

The Streamlit upload limit and TILI ingestion checks are configured to 1024 MB. Actual usable upload size can also depend on available RAM, workstation resources and browser/server behaviour. Large archives may take time and memory to process.

## 7. Configuration

Settings are in `config/settings.yaml`:

```yaml
app:
  name: TI Log Intelligence
  version: 0.2.0
  max_upload_mb: 1024
  max_zip_members: 1024
analysis:
  correlation_window_minutes: 10
  default_timezone: Europe/Berlin
```

The version and upload limits are loaded by TILI. The upload size is also set in `.streamlit/config.toml`.

After changing settings, stop and restart TILI. Keep `version` in sync with the release version. Do not increase upload limits unless the workstation has sufficient memory and disk capacity.

## 8. Basic workflow

1. Start TILI.
2. Upload the relevant log files or ZIP archive.
3. Review the Overview for file and event counts.
4. Open Findings and inspect the evidence for each detected pattern.
5. Review Timeline and Correlations as investigation aids.
6. Check Infrastructure Inventory for detected instance identifiers and card-expiry evidence.
7. Export CSV or JSON if required by your support workflow.

A detected pattern is not proof of root cause. Correlation means events occurred close together in time; it does not prove causation. Missing log evidence does not prove that a system is healthy.

## 9. Troubleshooting

**`python` or `py` is not recognised**  
Install Python 3.10+ and ensure it is added to PATH. Reopen the terminal.

**`streamlit` is not found**  
Activate `.venv` and run `python -m pip install -r requirements.txt`, then use `python -m streamlit run app.py`.

**`externally-managed-environment` on Debian/Ubuntu**  
Create and activate `.venv`; install packages inside it. Do not use `sudo pip`.

**Port 8501 is already in use**  
Run `python -m streamlit run app.py --server.port 8502` and open `http://localhost:8502`.

**Upload is rejected or the application runs out of memory**  
Check the configured 1024 MB limit and available workstation RAM. Large files may require a workstation with more memory. Do not assume that increasing the configured limit increases available system resources.

**No findings appear**  
Check that the file is text-based and supported. TILI uses a starter rule catalogue; not every product message or error is currently covered.

## 10. Security and responsible use

- Use approved, anonymised logs wherever possible.
- Logs may contain patient, practice, device, network, certificate or credential information.
- Do not upload passwords, private keys, access tokens or other secrets.
- Store exports only in approved locations.
- Keep TILI on the local workstation. Do not expose the Streamlit service to an untrusted network.
- Validate findings and recommendations against approved product documentation and surrounding log context.

## 11. Run the tests (optional)

With the virtual environment active:

```bash
python -m pytest -q
```

The tests cover selected functionality only; they are not complete validation of every log format or diagnostic rule.

---

**TILI v0.2 — Application version 0.2.0**
