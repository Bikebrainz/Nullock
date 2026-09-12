# Intruder project workspace (unreleased)

Intruder saves its staged request, target, payload sets, processing rules, grep
settings, request encoding, redirect behavior, scheduling settings and result
rows with the project. Switching back to the project or reopening it after a
clean app exit restores that workspace. Restoration does not start requests;
Start and Resume remain explicit user actions.

Connected browser clients receive target, rule and grep-setting updates. Edits
are sent in order, and older polling responses cannot replace newer typing.
Queued edits carry the project history generation so a stale client cannot apply
them to another project. Numeric settings wrap onto another row when needed.

The file is `intruder.json` beside `project.json`. It uses the existing Intruder
save/load format, so the current **SAVE** / **LOAD** buttons work with
portable copies. The CLI adds `nullock intruder save > attack.json`,
`nullock intruder load attack.json`, and `nullock intruder reset`.
No extra CLI command is needed for project restoration:
`nullock project open <name>` restores that project's workspace.

New projects and older projects without this file start with default settings.
All settings are reset between projects, including less visible payload rules,
grep terms and recursive seeds. Clearing captured HTTP history preserves the
independent Intruder workspace. Loading an empty saved-run document resets it;
the next project switch or clean exit saves that reset.

Workspace files are written atomically and limited to 64 MiB. If a save fails,
switching projects is refused and the current draft remains available for retry
or manual export. A malformed or unreadable incoming workspace also refuses
the switch before clearing the current draft. A save failure during shutdown
is reported to stderr and changes an otherwise successful exit code to 1.

This saves on project switch and clean exit, not after every keystroke. Abrupt
process termination can lose changes since the last save. Result rows preserve
the existing save format's status, timing, extracted values and completion state;
it does not contain raw response bodies. Back up the whole closed project folder
when moving an engagement between machines.

Regression coverage: `scripts/intruder_workspace_regression.py` verifies complete
configuration, binary request text, result rows, independent projects, same-project
reopen, startup restoration, idle restoration, stale edits, save failures and invalid files.
`Tests/ui/intruder_workspace_browser_test.cjs` checks target/option synchronization
between clients, project changes and page reloads. CI runs workspace checks on Windows, Linux and
macOS, and the browser workflow on Windows.
