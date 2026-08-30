# Release procedure

Releases use Semantic Versioning. The manifest, changelog, branch, annotated tag, and
GitHub Release must use the same version.

1. Create `release/vX.Y.Z` from current `main`.
2. Set `custom_components/jooan_nvr/manifest.json` to `X.Y.Z`.
3. Add the matching `CHANGELOG.md` section.
4. Run the complete local validation suite:

   ```bash
   python -m pytest
   python -m ruff check .
   python -m ruff format --check .
   python -m compileall -q custom_components jooan_discovery tests scripts
   python scripts/validate_isolation.py
   python scripts/validate_hacs.py
   python scripts/build_release.py --version X.Y.Z
   ```

5. Scan the working tree and all refs for secrets and private device data.
6. Push the release branch.
7. Wait for Tests, HACS validation, and Home Assistant validation to pass.
8. Merge or fast-forward the release branch into `main` and push `main`.
9. Create an annotated tag: `git tag -a vX.Y.Z -m "Release vX.Y.Z"`.
10. Push the tag: `git push origin vX.Y.Z`.
11. Let the tag workflow validate and publish the GitHub Release.
12. Confirm the ZIP and checksum are attached and the source archive contains
    `custom_components/jooan_nvr`.
13. Confirm HACS detects `vX.Y.Z` without `zip_release` configuration.
14. Install the update through HACS and restart Home Assistant.
15. Validate integration startup and one advancing camera stream.

Never publish a release from a dirty tree, move an existing version tag, include local
diagnostic artifacts, or submit the repository to the default HACS store without a
separate review.
