# Initial PyPI Publishing Instructions

Since this is the first time publishing `fastapi-jwt-harmony` to PyPI, you need to configure a pending publisher first.

## Steps to Configure Pending Publisher on PyPI:

1. **Go to PyPI**: https://pypi.org/
2. **Login to your account**
3. **Navigate to Publishing**: Click on your username → "Your projects" → "Publishing" (in the sidebar)
4. **Add a new pending publisher** with these details:
   - **PyPI Project Name**: `fastapi-jwt-harmony`
   - **GitHub Repository Owner**: `ivolnistov`
   - **GitHub Repository Name**: `fastapi-jwt-harmony`
   - **Workflow name**: `release.yml`
   - **Environment name**: `pypi` (this matches our workflow)

## Alternative: Manual First Publish

If you prefer to do the first publish manually:

1. **Create an API token on PyPI**:
   - Go to Account settings → API tokens
   - Create a new token for "fastapi-jwt-harmony"

2. **Publish manually**:
   ```bash
   # Download the artifacts from the latest workflow run
   gh run download 16272186164 -n dist

   # Upload to PyPI
   uv run --group build twine upload dist/*
   ```

3. **After first manual publish**, you can add trusted publisher to the existing project

## Current Status

The release workflow has successfully:
- ✅ Built the package
- ✅ Tested installation on all platforms
- ✅ Created a GitHub release
- ❌ Failed to publish to PyPI (pending publisher not configured)

The built artifacts are ready and can be downloaded from:
https://github.com/ivolnistov/fastapi-jwt-harmony/actions/runs/16272186164
