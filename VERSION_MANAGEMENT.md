# Version Management Guide

## 📋 Versioning Strategy

FastAPI JWT Harmony follows [Semantic Versioning (SemVer)](https://semver.org/):

```
MAJOR.MINOR.PATCH[-SUFFIX]
```

- **MAJOR** - Breaking changes, incompatible API changes
- **MINOR** - New features, backwards compatible
- **PATCH** - Bug fixes, backwards compatible
- **SUFFIX** - Pre-releases (alpha, beta, rc1, dev)

## 🔄 Current Process

### 1. Development
Version in `src/fastapi_jwt_harmony/version.py`:
```python
__version__ = '0.1.0-dev'  # Current dev version
```

### 2. Pre-releases
```bash
# Create pre-release
./release.sh prerelease alpha    # 0.1.0-alpha
./release.sh prerelease beta     # 0.1.0-beta
./release.sh prerelease rc1      # 0.1.0-rc1
```

### 3. Stable releases
```bash
# Create stable release
./release.sh release 0.1.0       # First release
./release.sh release 0.1.1       # Patch release
./release.sh release 0.2.0       # Minor release
./release.sh release 1.0.0       # Major release
```

## 🛠️ How Automation Works

### Release Script (`release.sh`)
1. **Validates** version format
2. **Checks** that tag doesn't exist
3. **Updates** `src/fastapi_jwt_harmony/version.py`
4. **Commits** version changes
5. **Creates tag** and pushes to GitHub
6. **Triggers** GitHub Actions workflow

### GitHub Actions
1. **Builds** package with new version
2. **Tests** installation
3. **Creates** GitHub Release
4. **Publishes** to PyPI (stable) or Test PyPI (pre-releases)

## 📝 Recommended Workflow

### For Features
```bash
# 1. Development in feature branch
git checkout -b feature/new-auth-method

# 2. Code + tests + documentation
# ...

# 3. Merge to main via PR
git checkout main
git merge feature/new-auth-method

# 4. Pre-release for testing
./release.sh prerelease alpha

# 5. After testing - stable release
./release.sh release 0.2.0  # Minor version for new feature
```

### For Bug Fixes
```bash
# 1. Hotfix branch
git checkout -b hotfix/token-validation

# 2. Fix the bug
# ...

# 3. Merge to main
git checkout main
git merge hotfix/token-validation

# 4. Patch release
./release.sh release 0.1.1  # Patch version for bug fix
```

### For Breaking Changes
```bash
# 1. Development in develop branch
git checkout develop

# 2. Breaking changes
# ...

# 3. Pre-releases for testing
./release.sh prerelease beta

# 4. Major release when ready
./release.sh release 1.0.0  # Major version for breaking changes
```

## 🎯 Versioning by Change Types

### Patch (0.1.0 → 0.1.1)
- 🐛 Bug fixes
- 📝 Documentation updates
- 🔧 Internal changes without API impact

### Minor (0.1.0 → 0.2.0)
- ✨ New features (backwards compatible)
- ⚡ Performance improvements
- 🔒 New security options
- 📦 New dependency groups

### Major (0.2.0 → 1.0.0)
- 💥 Breaking changes in API
- 🔄 Changes to public interfaces
- 📋 Removal of deprecated functions
- 🏗️ Architectural changes

## 🔍 Version Examples

```
0.1.0-dev      # Development
0.1.0-alpha    # First pre-release
0.1.0-beta     # Beta version
0.1.0-rc1      # Release candidate
0.1.0          # Stable release
0.1.1          # Bug fix
0.2.0          # New features
1.0.0          # First stable API
```

## 📋 Release Checklist

### Before Release
- [ ] All tests pass
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Breaking changes documented
- [ ] Migration guide created (for major versions)

### Pre-release
- [ ] `./release.sh prerelease alpha`
- [ ] Testing in test environment
- [ ] Collect feedback from users
- [ ] Fix found issues

### Stable Release
- [ ] `./release.sh release X.Y.Z`
- [ ] Verify in PyPI
- [ ] Update documentation
- [ ] Announce in discussions/social media

## 🚨 Error Recovery

### Wrong Version in Release
```bash
# 1. Delete tag locally and on GitHub
git tag -d vX.Y.Z
git push origin :refs/tags/vX.Y.Z

# 2. Delete release in GitHub UI
# 3. Fix version and create new release
./release.sh release X.Y.Z-fixed
```

### Version Rollback
```bash
# 1. Revert commit with version
git revert <commit-hash>

# 2. Update version to dev
echo "__version__ = 'X.Y.Z-dev'" > src/fastapi_jwt_harmony/version.py
git add src/fastapi_jwt_harmony/version.py
git commit -m "chore: bump version to X.Y.Z-dev"
```

## 🔧 Manual Version Management

If you need to change version manually:

```bash
# 1. Update version file
echo "__version__ = '1.2.3'" > src/fastapi_jwt_harmony/version.py

# 2. Verify changes are correct
python -c "from src.fastapi_jwt_harmony import __version__; print(__version__)"

# 3. Commit and create tag
git add src/fastapi_jwt_harmony/version.py
git commit -m "chore: bump version to 1.2.3"
git tag -a v1.2.3 -m "Release 1.2.3"
git push origin v1.2.3
```

## 📊 Release Monitoring

- **GitHub Releases**: https://github.com/your-org/fastapi-jwt-harmony/releases
- **PyPI**: https://pypi.org/project/fastapi-jwt-harmony/
- **Test PyPI**: https://test.pypi.org/project/fastapi-jwt-harmony/
- **GitHub Actions**: Monitor builds and publishing

---

**💡 Tip**: Always test pre-releases before stable releases!
