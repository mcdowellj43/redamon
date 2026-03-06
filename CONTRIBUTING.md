# Contributing to RedAmon

Thank you for your interest in contributing to RedAmon! This guide explains how to pick a task and submit a pull request.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Legal and Ethical Responsibilities](#legal-and-ethical-responsibilities)
- [How to Contribute](#how-to-contribute)
- [Development Workflow](#development-workflow)
  - [Branching Strategy](#branching-strategy)
  - [Commit Messages](#commit-messages)
  - [Pull Requests](#pull-requests)
- [Reporting Issues](#reporting-issues)
- [Security Vulnerabilities](#security-vulnerabilities)

---

## Code of Conduct

We are committed to providing a welcoming and inclusive experience for everyone. All participants are expected to:

- Be respectful and considerate in all interactions
- Accept constructive criticism gracefully
- Focus on what is best for the community and project
- Show empathy toward other contributors

Harassment, trolling, or abusive behavior of any kind will not be tolerated.

---

## Legal and Ethical Responsibilities

RedAmon is a security assessment framework. **All contributors must adhere to ethical and legal standards.**

Before contributing, read the [DISCLAIMER.md](DISCLAIMER.md) in full. Key points:

- **Only target systems you own or have explicit written authorization to test.** Unauthorized access is illegal under the CFAA, Computer Misuse Act, EU Directive 2013/40/EU, and similar laws.
- **Never include real-world target data** in commits, issues, or pull requests.
- **Use safe testing environments** such as the included `guinea_pigs/` VMs, HackTheBox, TryHackMe, DVWA, or your own lab infrastructure.
- **Do not add capabilities** designed for malicious use, detection evasion, or unauthorized access.

Contributors are personally responsible for ensuring their use of this tool complies with all applicable laws in their jurisdiction.

---

## How to Contribute

### 1. Pick a task

Browse the **[RedAmon Roadmap](https://github.com/users/samugit83/projects/1)** board. All tasks in the **"Up for grabs"** column are available for contributors.

Each issue describes:
- What the feature is about
- What already exists in the codebase
- What needs to be built (checklist)

### 2. Claim it

Comment on the issue to let others know you're working on it. The issue will be moved to **"In Progress"** on the board.

### 3. Fork and build

```bash
git clone https://github.com/<your-username>/RedAmon.git
cd RedAmon
```

For setup instructions (prerequisites, environment, Docker), see the [README.md](README.md#quick-start).

### 4. Submit a PR

Push your branch and open a pull request. The issue moves to **"In Review"** on the board. Once merged, it moves to **"Done"**.

---

## Development Workflow

### Branching Strategy

Create branches from `master` using the following naming convention:

| Prefix | Use Case | Example |
|--------|----------|---------|
| `feature/` | New functionality | `feature/add-shodan-integration` |
| `fix/` | Bug fixes | `fix/websocket-reconnect` |
| `refactor/` | Code restructuring | `refactor/agent-state-management` |
| `docs/` | Documentation only | `docs/update-api-reference` |

```bash
git checkout master
git pull origin master
git checkout -b feature/your-feature-name
```

### Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix | Description |
|--------|-------------|
| `feat:` | New feature |
| `fix:` | Bug fix |
| `refactor:` | Code restructuring (no behavior change) |
| `docs:` | Documentation changes |
| `chore:` | Build process, tooling, dependency updates |
| `test:` | Adding or updating tests |

Keep commits **atomic and focused** — each commit should represent a single logical change.

### Pull Requests

When your work is ready:

1. **Push** your branch to your fork:

   ```bash
   git push origin feature/your-feature-name
   ```

2. **Open a Pull Request** against the `master` branch.

3. **In your PR description**, include:
   - **Summary** — what changed and why (1-3 bullet points)
   - **How to test** — steps to verify the change
   - **Screenshots** — if there are UI changes
   - **Related issues** — link with `Closes #<issue-number>`

4. **Keep PRs focused.** Large features should be broken into smaller, reviewable PRs when possible.

5. **Ensure your branch is up to date** with `master` before requesting review:

   ```bash
   git fetch origin
   git rebase origin/master
   ```

---

## Reporting Issues

When opening an issue, include:

- **Clear title** describing the problem
- **Steps to reproduce** the issue
- **Expected behavior** vs. actual behavior
- **Environment details** — OS, Docker version, browser (if relevant)
- **Logs** — Relevant container logs (`docker compose logs <service>`)
- **Screenshots** — For UI issues

---

## Security Vulnerabilities

If you discover a security vulnerability in RedAmon itself (not in target systems being scanned), **do not open a public issue**. Instead:

1. Contact the maintainer directly (see below) with details of the vulnerability
2. Include steps to reproduce
3. Allow reasonable time for a fix before any public disclosure

We follow responsible disclosure practices and appreciate your help keeping RedAmon secure.

---

## Maintainer

**Samuele Giampieri** — creator and lead maintainer of RedAmon.

- [LinkedIn](https://www.linkedin.com/in/samuele-giampieri-b1b67597/)
- [Devergo Labs](https://www.devergolabs.com/)
- [GitHub](https://github.com/samugit83)

---

Questions? Open a discussion or issue on GitHub, or reach out to the maintainer. We're happy to help you get started!
