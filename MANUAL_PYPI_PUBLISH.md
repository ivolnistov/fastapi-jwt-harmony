# Manual PyPI Publishing

## Current Situation

The automated PyPI publishing via GitHub Actions is failing due to trusted publisher configuration mismatch. The error shows:

```
* `invalid-publisher`: valid token, but no corresponding publisher (Publisher with matching claims was not found)
```

## Manual Publishing Steps

1. **Create PyPI API Token** (if you don't have one):
   - Go to https://pypi.org/manage/account/token/
   - Create a token with scope "Entire account" or for specific project

2. **Set up `.pypirc` file** (optional):
   ```bash
   # Create ~/.pypirc with:
   [pypi]
     username = __token__
     password = <your-token-here>
   ```

3. **Upload the packages**:
   ```bash
   # Using uv (recommended)
   uv run --group build twine upload fastapi_jwt_harmony-0.1.1*

   # Or using pip
   pip install twine
   twine upload fastapi_jwt_harmony-0.1.1*
   ```

4. **After successful manual upload**, configure trusted publisher:
   - Go to https://pypi.org/manage/project/fastapi-jwt-harmony/settings/publishing/
   - Add a new publisher with these EXACT settings:
     - **Owner**: `ivolnistov`
     - **Repository name**: `fastapi-jwt-harmony`
     - **Workflow name**: `release.yml`
     - **Environment name**: `pypi` (optional but recommended)

## Verification

After manual upload, verify the package:
```bash
pip install fastapi-jwt-harmony==0.1.1
```

## Files Ready for Upload

- `fastapi_jwt_harmony-0.1.1-py3-none-any.whl` (23 KB)
- `fastapi_jwt_harmony-0.1.1.tar.gz` (45 KB)

Both files have been built and tested on all platforms successfully.
