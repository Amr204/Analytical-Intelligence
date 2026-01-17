# 🐙 Git Workflow Guide

> Standard operating procedures for working with the Analytical-Intelligence repository

---

## Table of Contents

- [Quick Start](#quick-start-first-time-setup)
- [Branching Model](#branching-model-repo-standard)
- [Commit Message Standard](#commit-message-standard-project-specific)
- [Repo Hygiene](#repo-hygiene-very-important)
- [Common Recipes](#common-recipes-copypaste)
- [Multi-server Deployment](#multi-server-deployment-tip)
- [Safety Notes](#safety-notes)
- [Troubleshooting Git](#troubleshooting-git)

---

## Quick Start (First-time Setup)

```bash
# 1. Clone the repository
git clone https://github.com/Amr204/Analytical-Intelligence.git
cd Analytical-Intelligence

# 2. Configure identity (if new machine)
git config user.name "Your Name"
git config user.email "your.email@example.com"

# 3. Verify remote
git remote -v
# Expected: origin  https://github.com/... (fetch/push)

# 4. Pull latest changes
git pull origin main

# 5. Create local .env (never commit this!)
cp .env.example .env
```

---

## Branching Model (Repo Standard)

We use a standard stable/development flow.

| Branch | Purpose | Protection |
|--------|---------|------------|
| `main` | **Stable Production**. Deployed to Analyzer/Sensors. | Protected (Require PR) |
| `develop` | **Integration**. All new features merge here first. | Semi-protected |
| `feat/*` | Feature branches (e.g., `feat/add-new-sensor`). | Temporary |
| `fix/*` | Bug fixes (e.g., `fix/backend-crash`). | Temporary |

### Release Flow
`feat/xyz` → Pull Request → `develop` → Testing → Pull Request → `main` → tag `v1.x`

> [!NOTE]
> If `develop` does not exist yet, treat `main` as the source of truth and create `develop` from it.

---

## Commit Message Standard (Project-specific)

Format: `type: description`

| Type | Description | Example |
|------|-------------|---------|
| `feat` | New feature | `feat: add alerting for port scanning` |
| `fix` | Bug fix | `fix: correct threshold in RF model` |
| `docs` | Documentation | `docs: update troubleshooting runbook` |
| `chore` | Maintenance | `chore: update .gitignore for models` |
| `refactor`| Code structure | `refactor: split ingest router` |
| `build` | Dependencies | `build: pin scikit-learn version` |

---

## Repo Hygiene (VERY IMPORTANT)

### A. Large Files / Models
> [!WARNING]
> Do NOT commit large model files (`.joblib`) directly to Git!

- **Policy**: `random_forest.joblib` (~65MB) is ignored via `.gitignore`.
- **How to manage**:
  - Keep models in `models/RF/` locally.
  - Backup models externally (S3, Drive, or separate LFS repo).
  - If LFS is absolutely needed:
    ```bash
    git lfs install
    git lfs track "*.joblib"
    ```

### B. Secrets (.env)
> [!DANGER]
> **NEVER commit `.env` files containing `INGEST_API_KEY` or DB passwords.**

- Check status before adding:
  ```bash
  git status
  # Ensure .env is NOT listed (should be ignored)
  ```
- Always update `.env.example` with *safe defaults* if you add new variables.

### C. Generated Files
- `__pycache__`, `venv/`, and logs must be ignored.
- Use `git clean -fdX` to remove ignored files locally if things get messy.

---

## Common Recipes (Copy/Paste)

### 1. Create a feature branch
**Use when:** Starting new work.
```bash
git checkout main
git pull
git checkout -b feat/my-new-feature
```

### 2. Push branch and set upstream
**Use when:** Saving work to server.
```bash
git push -u origin feat/my-new-feature
```

### 3. Sync your branch
**Use when:** `main` has updated and you need those changes.
```bash
git fetch origin
git rebase origin/main
# Fix conflicts if any, then:
git push --force-with-lease
```

### 4. Promote to Stable
**Use when:** Preparing release.
```bash
# Merge develop into main
git checkout main
git pull
git merge develop
git push origin main
```

### 5. Hotfix Flow
**Use when:** Critical bug in production.
```bash
git checkout main
git checkout -b fix/critical-bug
# ... fix code ...
git commit -m "fix: resolve critical bug"
git checkout main
git merge fix/critical-bug
git push origin main
# Backport to develop
git checkout develop
git merge fix/critical-bug
git push origin develop
```

### 6. Undo Safely

**Discard local file changes:**
```bash
git restore <file>
```

**Unstage file (remove from green to red status):**
```bash
git restore --staged <file>
```

**Revert committed change (Safe):**
```bash
git revert <COMMIT_HASH>
```

### 7. Resolve Merge Conflicts

If `git merge` fails:
1. Run `git status` to see conflicting files.
2. Edit files (look for `<<<<<<< HEAD`).
3. Fix code, remove markers.
4. Add fixed files: `git add <file>`
5. Continue: `git merge --continue` (or rebase --continue)

### 8. Stash Changes
**Use when:** You need to switch branches but aren't ready to commit.
```bash
git stash
git checkout other-branch
# ... do work ...
git checkout original-branch
git stash pop
```

### 9. Tags and Releases
**Use when:** Marking a deployment point.
```bash
git tag -a v1.2.0 -m "Release v1.2.0: Added new sensor type"
git push origin v1.2.0
```

### 10. Fix Non-Fast-Forward Error
**Symptoms:** `git push` fails because legitimate history changed.
**Fix:**
```bash
git pull --rebase origin <branch_name>
git push origin <branch_name>
```

### 11. Detached HEAD Fix
**Use when:** You accidentally checked out a commit, made changes, and want to save them.
```bash
git switch -c temp-branch
# Now merge temp-branch where you want it
```

### 12. Line Endings (Windows)
**Use when:** Scripts fail on Linux due to `\r\n`.
```bash
git config --global core.autocrlf input
```

---

## Multi-server Deployment Tip

This system runs on multiple servers (Analyzer + Sensors).

**Deployment Checklist:**
1. ✅ **Test locally** or on staging first.
2. ✅ **Push to `main`**.
3. ✅ **On Analyzer:**
   ```bash
   git pull origin main
   bash scripts/analysis_up.sh
   # Verify health endpoint
   ```
4. ✅ **On Sensors:**
   ```bash
   git pull origin main
   bash scripts/sensor_up.sh
   ```

> [!TIP]
> Only deploy changes to sensors after confirming the Analyzer is stable.

---

## Safety Notes

- 🛑 **Avoid `git push --force`** on shared branches (`main`, `develop`).
  - Use `git push --force-with-lease` if you must (e.g., after rebase).
- 🛑 **Avoid `git reset --hard`** unless you are 100% sure you want to lose uncommitted work.
- 🛑 **Never delete `main` branch.**

---

## Troubleshooting Git

### "Nothing to commit"
- Check `git status`. You might have ignored files or haven't added them (`git add .`).

### "Untracked files"
- These are new files. `git add <file>` to include them.

### "Permission denied (publickey)"
- SSH key missing.
- Fix: `ssh-keygen -t ed25519` → Add `~/.ssh/id_ed25519.pub` to GitHub Settings.

### "Merge conflict"
- See Recipe #7. Do not panic.

---
