#!/usr/bin/env python3
"""Exercise the actual native Repeater controls in Qt's QML runtime."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def block(source, start):
    """Extract a QML component, ignoring braces inside strings and comments."""
    opening = source.index('{', start)
    depth, quote, escaped, line_comment, block_comment = 0, '', False, False, False
    i = opening
    while i < len(source):
        char, pair = source[i], source[i:i + 2]
        if line_comment:
            if char == '\n': line_comment = False
        elif block_comment:
            if pair == '*/': block_comment = False; i += 1
        elif quote:
            if escaped: escaped = False
            elif char == '\\': escaped = True
            elif char == quote: quote = ''
        elif pair == '//': line_comment = True; i += 1
        elif pair == '/*': block_comment = True; i += 1
        elif char in ('"', "'"): quote = char
        elif char == '{': depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0: return source[start:i + 1]
        i += 1
    raise AssertionError('unclosed QML block')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('qml', nargs='?', default=shutil.which('qml'))
    runner = parser.parse_args().qml
    assert runner, 'Qt qml runtime is required'
    source = (ROOT / 'Src/App/app.qml').read_text(encoding='utf-8')
    components = '\n'.join(block(source, source.index('component ' + name + ' :'))
                           for name in ['Cell', 'HeaderCell', 'AccentButton'])
    field = source.index('id: repeaterHostField')
    controls = block(source, source.rfind('Rectangle {', 0, field))
    harness = '''import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
ApplicationWindow {
    id: root
    width: 1480; height: 180; visible: true
    property color accent: "orange"
    property color text: "white"
    property color pane: "black"
    property color line: "gray"
    QtObject {
        id: repeater
        property string host: "old.fixture"
        property int port: 80
        property bool useTls: false
        property string requestText: "GET / HTTP/1.1\\r\\n\\r\\n"
        property string statusLine: ""
        property bool busy: false
        property bool cancelling: false
        property int sends: 0
        property int stops: 0
        property int clears: 0
        function send() { throw new Error("native control called blocking Send") }
        function sendAsync() { sends++; busy = true }
        function cancel() { stops++; cancelling = true }
        function clear() { clears++; requestText = "" }
    }
    COMPONENTS
    ColumnLayout { anchors.fill: parent; CONTROLS }
    function check(ok, message) { if (!ok) throw new Error(message) }
    function button(item, label) {
        if (item.label === label) return item
        const children = item.children || []
        for (let i = 0; i < children.length; ++i) {
            const found = button(children[i], label)
            if (found) return found
        }
        return null
    }
    Component.onCompleted: Qt.callLater(function() {
        try {
            const send = button(root.contentItem, "Send")
            const stop = button(root.contentItem, "Stop")
            const clear = button(root.contentItem, "Clear")
            check(send && stop && clear, "missing native controls")
            for (const port of ["", "0", "65536", "invalid"]) {
                repeaterPortField.text = port
                check(!send.enabled, "Send enabled for invalid port: " + port)
            }
            repeaterPortField.text = "8081"
            repeaterHostField.text = "   "
            check(!send.enabled, "Send enabled for blank host")
            repeaterHostField.text = "  new.fixture  "
            check(send.enabled, "valid draft cannot send")
            send.clicked()
            check(repeater.sends === 1 && repeater.busy, "Send did not start background work")
            check(repeater.host === "new.fixture" && repeater.port === 8081, "visible target was not committed")
            check(!send.enabled && !clear.enabled && stop.visible, "busy controls are incorrect")
            stop.clicked()
            check(repeater.stops === 1 && repeater.cancelling, "Stop did not cancel")
            check(!stop.enabled && stop.label === "Stopping...", "pending Stop state is incorrect")
            repeater.busy = false
            repeater.cancelling = false
            check(!stop.visible && send.enabled && clear.enabled, "controls did not recover after completion")
            clear.clicked()
            check(repeater.clears === 1 && !send.enabled, "empty draft can send after Clear")
            console.log("PASS: native Send uses the worker, commits visible targets, validates inputs and exposes Stop/busy states")
            Qt.exit(0)
        } catch (error) { console.error(error); Qt.exit(1) }
    })
}
'''.replace('COMPONENTS', components).replace('CONTROLS', controls)
    with tempfile.TemporaryDirectory(prefix='nullock-native-controls-') as temporary:
        file = Path(temporary) / 'controls.qml'
        file.write_text(harness, encoding='utf-8')
        result = subprocess.run([runner, str(file)], capture_output=True, text=True, timeout=20,
            env={**os.environ, 'QT_QPA_PLATFORM': 'offscreen', 'QT_QUICK_BACKEND': 'software',
                 'QT_QUICK_CONTROLS_STYLE': 'Basic', 'QT_FORCE_STDERR_LOGGING': '1'},
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        output = result.stdout + result.stderr
        print(output, end='')
        assert result.returncode == 0 and 'PASS: native Send' in output, f'native QML controls failed ({result.returncode})'


if __name__ == '__main__':
    main()
