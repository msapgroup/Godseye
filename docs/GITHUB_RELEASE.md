# GODSEYE GitHub Release / Upload

This directory is a clean, Docker-free Raspberry Pi working copy.

## Upload to the existing Godseye repository

1. Extract the ZIP.
2. Open the extracted directory.
3. Copy its contents into a fresh clone of `msapgroup/Godseye`.
4. Review `.env.example` before deployment.
5. Commit and push.

```bash
git clone https://github.com/msapgroup/Godseye.git
cd Godseye
# copy the GODSEYE files here
git add .
git commit -m "Build GODSEYE Raspberry Pi network intelligence app"
git push origin main
```

Do not commit `/data`, `.env`, secrets, or generated databases.

## Raspberry Pi installation

```bash
sudo bash install.sh
```

The installer installs the native discovery/diagnostic packages, creates the `godseye` service account, installs the Python virtual environment, and enables the web/scanner services.

## Verify before publishing

```bash
python3 -m py_compile app/*.py
PYTHONPATH=. pytest -q
```

The working build should report 3 passing tests.
