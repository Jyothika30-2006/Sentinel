## Summary

<!-- What does this PR do? One or two sentences. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] New tool (cybersecurity)
- [ ] Safety / sandbox change
- [ ] Documentation
- [ ] Test

## Safety checklist (required for any code change)

- [ ] Tool whitelist unchanged unless adding a new `registry` entry
- [ ] File-touching code still routes through the sandbox
- [ ] No `eval`/`exec`/arbitrary shell introduced
- [ ] `python -m pytest` passes

## Test plan

<!-- How did you verify this? -->
