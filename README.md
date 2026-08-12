# CI/CD Container Release Gate Microservice

A deterministic security policy microservice that decides whether a GitHub Actions workflow run may promote a container image.

## Setup & Local Execution

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run tests:
   ```bash
   pytest test_app.py -v
   ```

3. Start local development server:
   ```bash
   uvicorn app:app --reload --port 8000
   ```

4. Test API locally:
   ```bash
   curl -X POST http://localhost:8000/release-gate \
     -H "Content-Type: application/json" \
     -d '{
       "target": "preview",
       "event": "pull_request",
       "ref": "refs/heads/feature",
       "workflow": {
         "trigger": "pull_request",
         "permissions": {"contents":"read", "packages":"write", "id-token":"none"},
         "testsPassed": true, "matrixComplete": true, "failFast": false,
         "actions": [{"owner":"actions", "name":"checkout", "ref":"v4"}]
       },
       "image": {
         "multiStage": true, "runsAsRoot": false, "secretMode": "buildkit",
         "criticalVulnerabilities": 0, "digestPinned": true
       }
     }'
   ```

## GitHub Actions Evidence Workflow

The workflow at `.github/workflows/release_gate.yml`:
- Workflow Name: `TDS GA7 Release Gate`
- Triggers on: `push` to `main`
- Mandatory Step: `TDS identity: 24f2007687@ds.study.iitm.ac.in`
