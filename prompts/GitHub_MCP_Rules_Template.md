GitHub MCP Server Workflow Rules Template

Purpose
- Standardize how GitHub MCP tools target repositories and how defaults are configured for a workspace or product.

Defaults
- All GitHub MCP server tool invocations must use the following defaults unless explicitly overridden:
  - "owner": "<GITHUB_OWNER>"
  - "repo": "<GITHUB_REPO>"

Override Guidance
- Only override defaults when the task explicitly targets a different repository.
- Document the override inline with rationale (e.g., cross-repo dependency, upstream fork, archived mirror).

Safety and Credentials
- Never echo tokens or secrets in logs or output.
- Prefer read-only operations when validating setups (e.g., list-issues, get-content).
- Changes to repository settings, branch protections, or workflow triggers may require change control.

Common Operations (Examples)
- Content retrieval:
  - Tool: get-content
  - Args (example):
    {
      "owner": "<GITHUB_OWNER>",
      "repo": "<GITHUB_REPO>",
      "path": "README.md",
      "ref": "main"
    }
- Pull requests:
  - Tool: create-pull-request
  - Args (example):
    {
      "owner": "<GITHUB_OWNER>",
      "repo": "<GITHUB_REPO>",
      "title": "Fix: Update config defaults",
      "head": "feature/update-defaults",
      "base": "main",
      "body": "Summary of changes and validation notes.",
      "draft": true
    }
- Issues:
  - Tool: create-issue
  - Args (example):
    {
      "owner": "<GITHUB_OWNER>",
      "repo": "<GITHUB_REPO>",
      "title": "Triage: build pipeline fails on Windows",
      "body": "Observed failure in workflow X...",
      "labels": ["triage", "ci"]
    }
- Workflows:
  - Tool: trigger-workflow
  - Args (example):
    {
      "owner": "<GITHUB_OWNER>",
      "repo": "<GITHUB_REPO>",
      "workflow_id": "ci.yml",
      "ref": "main",
      "inputs": {
        "run_mode": "quick"
      }
    }

Conventions
- Branch naming: feature/<short-desc>, fix/<short-desc>, chore/<short-desc>
- Commit messages: Conventional Commits (e.g., feat:, fix:, chore:, docs:, refactor:, test:)
- PR description: Include purpose, approach, risks, test evidence, and rollback.

Review Checklist (PRs)
- Scope limited and well-described
- CI status green; workflows passing
- Security-sensitive changes called out explicitly
- Backwards compatibility considered
- Rollback path identified (revert, toggle, or config)

Labels and Triage
- Use consistent labels for automation and dashboards (e.g., "triage", "security", "docs", "breaking-change")
- Add environment scope labels when relevant (e.g., "windows", "linux", "oracle", "mysql")

Notes
- Keep this file under support_workspace/templates/ and instantiate per workspace with concrete defaults.
- Update <GITHUB_OWNER>/<GITHUB_REPO> during initialization of a new environment.
