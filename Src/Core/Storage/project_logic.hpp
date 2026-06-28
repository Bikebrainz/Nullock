#pragma once

// Pure project-name validation, split out of project_store.cpp so a unit test can
// link it against Qt6::Core alone. A project name becomes a directory under the
// projects root (projectsRoot() + "/" + name), so this is the path-traversal guard
// for project storage -- a name that escapes the root, names a Windows device, or
// carries a control byte must be refused before any mkpath/open.

#include <QString>

namespace Nullock::Core::ProjectLogic {

// True only for a benign single-segment project name. Rejects: empty / > 64 chars;
// NUL, '/', '\\', "..", a leading '.'/' ' or trailing '.'/' ' (Win32 silent-strip
// to a sibling), a control char (< 0x20); a Windows reserved device name -- checked
// against the STEM before the first dot, so "CON.txt"/"COM1.log" are caught too;
// and any char outside [letter/number] '_' '-' ' ' '.'. No surviving name can
// produce a path segment outside the projects root.
bool isValidProjectName(const QString &name);

} // namespace Nullock::Core::ProjectLogic
