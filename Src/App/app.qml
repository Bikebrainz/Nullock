import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ApplicationWindow {
    id: root
    visible: true
    width: 1480
    height: 900
    title: "Nullock"
    color: "#0a0a0a"

    readonly property color accent:    "#ff8c1a"
    readonly property color text:      "#80f0c0"
    readonly property color dim:       "#5a5a5a"
    readonly property color rowAlt:    "#141414"
    readonly property color rowEven:   "#1c1c1c"
    readonly property color rowSelect: "#3a2010"
    readonly property color pane:      "#0f0f0f"
    readonly property color line:      "#222"

    component Cell : Text {
        color: root.text
        font.family: "Consolas"
        font.pixelSize: 12
        elide: Text.ElideRight
        verticalAlignment: Text.AlignVCenter
        leftPadding: 6
        rightPadding: 6
    }

    component HeaderCell : Text {
        color: root.accent
        font.family: "Consolas"
        font.pixelSize: 12
        font.bold: true
        leftPadding: 6
        rightPadding: 6
        verticalAlignment: Text.AlignVCenter
    }

    component TabHeader : Rectangle {
        property string label
        property bool active
        signal clicked
        implicitWidth: txt.implicitWidth + 24
        implicitHeight: 26
        color: active ? "#1a1a1a" : "transparent"
        border.color: active ? root.accent : "transparent"
        border.width: 1
        Text {
            id: txt
            anchors.centerIn: parent
            text: parent.label
            color: parent.active ? root.accent : root.dim
            font.family: "Consolas"
            font.pixelSize: 13
            font.bold: parent.active
        }
        MouseArea { anchors.fill: parent; onClicked: parent.clicked() }
    }

    component AccentButton : Rectangle {
        property string label
        signal clicked
        implicitWidth: btxt.implicitWidth + 16
        implicitHeight: 22
        color: hovered.containsMouse ? "#3a2010" : "transparent"
        border.color: root.accent
        border.width: 1
        Text {
            id: btxt
            anchors.centerIn: parent
            text: parent.label
            color: root.accent
            font.family: "Consolas"
            font.pixelSize: 12
        }
        MouseArea {
            id: hovered
            anchors.fill: parent
            hoverEnabled: true
            onClicked: parent.clicked()
        }
    }

    property int currentTab: 0

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        // Title + tab bar
        Rectangle {
            color: "#0a0a0a"
            Layout.fillWidth: true
            implicitHeight: 38
            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 12
                anchors.rightMargin: 12
                spacing: 12
                Text {
                    text: "Nullock"
                    color: root.accent
                    font.pixelSize: 16
                    font.bold: true
                }
                Item { width: 18 }
                TabHeader { label: "Proxy";     active: root.currentTab === 0; onClicked: root.currentTab = 0 }
                TabHeader { label: "Scope";     active: root.currentTab === 1; onClicked: root.currentTab = 1 }
                TabHeader { label: "Repeater";  active: root.currentTab === 2; onClicked: root.currentTab = 2 }
                TabHeader { label: "Intercept"; active: root.currentTab === 3; onClicked: root.currentTab = 3 }
                Item { Layout.fillWidth: true }
            }
        }
        Rectangle { Layout.fillWidth: true; height: 1; color: root.line }

        StackLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: root.currentTab

            // ── Tab 0: Proxy (HTTP history + click-to-inspect) ─────────────────
            ColumnLayout {
                spacing: 0
                SplitView {
                    id: split
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    orientation: Qt.Vertical

                    ColumnLayout {
                        SplitView.fillHeight: true
                        SplitView.minimumHeight: 120
                        spacing: 0

                        Rectangle {
                            color: "#000000"
                            Layout.fillWidth: true
                            height: 24
                            RowLayout {
                                anchors.fill: parent
                                spacing: 0
                                HeaderCell { text: "#";      Layout.preferredWidth: 50 }
                                HeaderCell { text: "Host";   Layout.preferredWidth: 280 }
                                HeaderCell { text: "Method"; Layout.preferredWidth: 70 }
                                HeaderCell { text: "URL";    Layout.fillWidth: true; Layout.minimumWidth: 200 }
                                HeaderCell { text: "Status"; Layout.preferredWidth: 60 }
                                HeaderCell { text: "MIME";   Layout.preferredWidth: 130 }
                                HeaderCell { text: "Params"; Layout.preferredWidth: 60 }
                                HeaderCell { text: "TLS";    Layout.preferredWidth: 40 }
                                HeaderCell { text: "IP";     Layout.preferredWidth: 130 }
                                HeaderCell { text: "Time";   Layout.preferredWidth: 110 }
                            }
                        }

                        ListView {
                            id: history
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            model: proxyModel
                            clip: true
                            currentIndex: -1
                            highlightFollowsCurrentItem: false
                            ScrollBar.vertical: ScrollBar {}

                            delegate: Rectangle {
                                width: history.width
                                height: 22
                                color: ListView.isCurrentItem
                                    ? root.rowSelect
                                    : ((index % 2 === 0) ? root.rowEven : root.rowAlt)

                                MouseArea {
                                    anchors.fill: parent
                                    onClicked: history.currentIndex = index
                                }

                                RowLayout {
                                    anchors.fill: parent
                                    spacing: 0
                                    Cell { text: rowId;                    Layout.preferredWidth: 50 }
                                    Cell { text: host;                     Layout.preferredWidth: 280 }
                                    Cell { text: method;                   Layout.preferredWidth: 70 }
                                    Cell { text: url;                      Layout.fillWidth: true; Layout.minimumWidth: 200 }
                                    Cell { text: statusCode || "";         Layout.preferredWidth: 60 }
                                    Cell { text: mime;                     Layout.preferredWidth: 130 }
                                    Cell { text: params > 0 ? params : ""; Layout.preferredWidth: 60 }
                                    Cell { text: tls ? "✓" : "";           Layout.preferredWidth: 40; horizontalAlignment: Text.AlignHCenter }
                                    Cell { text: ip;                       Layout.preferredWidth: 130 }
                                    Cell { text: timestamp;                Layout.preferredWidth: 110 }
                                }
                            }
                        }
                    }

                    Rectangle {
                        SplitView.preferredHeight: 280
                        SplitView.minimumHeight: 100
                        color: root.pane
                        border.color: root.line
                        border.width: 1

                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: 6
                            spacing: 4

                            Text {
                                Layout.fillWidth: true
                                text: history.currentIndex >= 0
                                    ? proxyModel.summaryAt(history.currentIndex)
                                    : "select a row to inspect"
                                color: history.currentIndex >= 0 ? root.accent : root.dim
                                font.family: "Consolas"
                                font.pixelSize: 12
                                elide: Text.ElideRight
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                spacing: 6

                                ColumnLayout {
                                    Layout.fillWidth: true
                                    Layout.fillHeight: true
                                    spacing: 2
                                    HeaderCell { text: "Request" }
                                    ScrollView {
                                        Layout.fillWidth: true
                                        Layout.fillHeight: true
                                        TextArea {
                                            readOnly: true
                                            wrapMode: TextArea.NoWrap
                                            font.family: "Consolas"
                                            font.pixelSize: 12
                                            color: root.text
                                            background: Rectangle { color: "#080808"; border.color: root.line; border.width: 1 }
                                            text: history.currentIndex >= 0
                                                ? proxyModel.requestRawAt(history.currentIndex)
                                                : ""
                                        }
                                    }
                                }

                                ColumnLayout {
                                    Layout.fillWidth: true
                                    Layout.fillHeight: true
                                    spacing: 2
                                    RowLayout {
                                        HeaderCell { text: "Response" }
                                        Item { Layout.fillWidth: true }
                                        AccentButton {
                                            label: "Send to Repeater"
                                            visible: history.currentIndex >= 0 && typeof repeater !== "undefined"
                                            onClicked: {
                                                repeater.loadFromHistory(history.currentIndex)
                                                root.currentTab = 2
                                            }
                                        }
                                    }
                                    ScrollView {
                                        Layout.fillWidth: true
                                        Layout.fillHeight: true
                                        TextArea {
                                            readOnly: true
                                            wrapMode: TextArea.NoWrap
                                            font.family: "Consolas"
                                            font.pixelSize: 12
                                            color: root.text
                                            background: Rectangle { color: "#080808"; border.color: root.line; border.width: 1 }
                                            text: history.currentIndex >= 0
                                                ? proxyModel.responseRawAt(history.currentIndex)
                                                : ""
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ── Tab 1: Scope ───────────────────────────────────────────────────
            RowLayout {
                spacing: 12
                Layout.margins: 12

                // In-scope column
                Rectangle {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    color: root.pane
                    border.color: root.line
                    border.width: 1
                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 8
                        spacing: 6

                        HeaderCell { text: "In scope (" + projectStore.inScopeList.length + ")" }

                        ListView {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            clip: true
                            model: projectStore.inScopeList
                            ScrollBar.vertical: ScrollBar {}
                            delegate: Rectangle {
                                width: ListView.view.width
                                height: 24
                                color: (index % 2 === 0) ? root.rowEven : root.rowAlt
                                RowLayout {
                                    anchors.fill: parent
                                    spacing: 6
                                    anchors.leftMargin: 6
                                    Cell { text: modelData; Layout.fillWidth: true }
                                    AccentButton {
                                        label: "−"
                                        onClicked: projectStore.removeInScope(modelData)
                                    }
                                    Item { width: 4 }
                                }
                            }
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 6
                            TextField {
                                id: inField
                                Layout.fillWidth: true
                                placeholderText: "e.g. *.example.com"
                                color: root.text
                                font.family: "Consolas"
                                font.pixelSize: 12
                                background: Rectangle { color: "#080808"; border.color: root.line; border.width: 1 }
                                onAccepted: {
                                    if (text.length > 0) {
                                        projectStore.addInScope(text)
                                        text = ""
                                    }
                                }
                            }
                            AccentButton {
                                label: "+ add"
                                onClicked: {
                                    if (inField.text.length > 0) {
                                        projectStore.addInScope(inField.text)
                                        inField.text = ""
                                    }
                                }
                            }
                        }

                        Text {
                            text: "(empty list means everything is in scope)"
                            color: root.dim
                            font.family: "Consolas"
                            font.pixelSize: 10
                            visible: projectStore.inScopeList.length === 0
                        }
                    }
                }

                // Out-of-scope column
                Rectangle {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    color: root.pane
                    border.color: root.line
                    border.width: 1
                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 8
                        spacing: 6

                        HeaderCell { text: "Out of scope (" + projectStore.outOfScopeList.length + ")" }

                        ListView {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            clip: true
                            model: projectStore.outOfScopeList
                            ScrollBar.vertical: ScrollBar {}
                            delegate: Rectangle {
                                width: ListView.view.width
                                height: 24
                                color: (index % 2 === 0) ? root.rowEven : root.rowAlt
                                RowLayout {
                                    anchors.fill: parent
                                    spacing: 6
                                    anchors.leftMargin: 6
                                    Cell { text: modelData; Layout.fillWidth: true }
                                    AccentButton {
                                        label: "−"
                                        onClicked: projectStore.removeOutOfScope(modelData)
                                    }
                                    Item { width: 4 }
                                }
                            }
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 6
                            TextField {
                                id: outField
                                Layout.fillWidth: true
                                placeholderText: "e.g. *.duckduckgo.com"
                                color: root.text
                                font.family: "Consolas"
                                font.pixelSize: 12
                                background: Rectangle { color: "#080808"; border.color: root.line; border.width: 1 }
                                onAccepted: {
                                    if (text.length > 0) {
                                        projectStore.addOutOfScope(text)
                                        text = ""
                                    }
                                }
                            }
                            AccentButton {
                                label: "+ add"
                                onClicked: {
                                    if (outField.text.length > 0) {
                                        projectStore.addOutOfScope(outField.text)
                                        outField.text = ""
                                    }
                                }
                            }
                        }

                        Text {
                            text: "(out-of-scope wins over in-scope)"
                            color: root.dim
                            font.family: "Consolas"
                            font.pixelSize: 10
                        }
                    }
                }
            }

            // ── Tab 2: Repeater ───────────────────────────────────────────────
            Item {
                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 8
                    spacing: 6

                    // Target row
                    Rectangle {
                        Layout.fillWidth: true
                        height: 32
                        color: root.pane
                        border.color: root.line
                        border.width: 1
                        RowLayout {
                            anchors.fill: parent
                            anchors.leftMargin: 8
                            anchors.rightMargin: 8
                            spacing: 8
                            HeaderCell { text: "Target" }
                            TextField {
                                Layout.preferredWidth: 280
                                placeholderText: "host"
                                text: repeater.host
                                color: root.text
                                font.family: "Consolas"
                                font.pixelSize: 12
                                background: Rectangle { color: "#080808"; border.color: root.line; border.width: 1 }
                                onEditingFinished: repeater.host = text
                            }
                            HeaderCell { text: ":" }
                            TextField {
                                Layout.preferredWidth: 80
                                text: "" + repeater.port
                                color: root.text
                                font.family: "Consolas"
                                font.pixelSize: 12
                                background: Rectangle { color: "#080808"; border.color: root.line; border.width: 1 }
                                onEditingFinished: repeater.port = parseInt(text) || 0
                            }
                            AccentButton {
                                label: repeater.useTls ? "TLS on" : "TLS off"
                                onClicked: repeater.useTls = !repeater.useTls
                            }
                            Item { Layout.fillWidth: true }
                            Cell { text: repeater.statusLine; color: root.accent; Layout.preferredWidth: 200 }
                            AccentButton {
                                label: repeater.busy ? "..." : "Send"
                                onClicked: repeater.send()
                            }
                            AccentButton {
                                label: "Clear"
                                onClicked: repeater.clear()
                            }
                        }
                    }

                    // Request / Response side-by-side
                    RowLayout {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        spacing: 6

                        ColumnLayout {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            spacing: 2
                            HeaderCell { text: "Request (editable)" }
                            ScrollView {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                clip: true
                                TextArea {
                                    wrapMode: TextArea.NoWrap
                                    font.family: "Consolas"
                                    font.pixelSize: 12
                                    color: root.text
                                    background: Rectangle { color: "#080808"; border.color: root.line; border.width: 1 }
                                    text: repeater.requestText
                                    onEditingFinished: repeater.requestText = text
                                }
                            }
                        }

                        ColumnLayout {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            spacing: 2
                            HeaderCell { text: "Response" }
                            ScrollView {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                clip: true
                                TextArea {
                                    readOnly: true
                                    wrapMode: TextArea.NoWrap
                                    font.family: "Consolas"
                                    font.pixelSize: 12
                                    color: root.text
                                    background: Rectangle { color: "#080808"; border.color: root.line; border.width: 1 }
                                    text: repeater.responseText
                                }
                            }
                        }
                    }
                }
            }

            // ── Tab 3: Intercept ──────────────────────────────────────────────
            Item {
                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 8
                    spacing: 6

                    // Toggle + queue counter
                    Rectangle {
                        Layout.fillWidth: true
                        height: 32
                        color: root.pane
                        border.color: root.line
                        border.width: 1
                        RowLayout {
                            anchors.fill: parent
                            anchors.leftMargin: 8
                            anchors.rightMargin: 8
                            spacing: 12
                            AccentButton {
                                label: intercept.enabled ? "Intercept ON" : "Intercept OFF"
                                onClicked: intercept.enabled = !intercept.enabled
                            }
                            Cell {
                                text: intercept.enabled
                                      ? ("queue: " + intercept.queueDepth)
                                      : "pass-through (toggle to pause)"
                                color: intercept.enabled ? root.text : root.dim
                            }
                            Item { Layout.fillWidth: true }
                            AccentButton {
                                label: "Forward all"
                                visible: intercept.queueDepth > 0
                                onClicked: intercept.forwardAll()
                            }
                        }
                    }

                    // Current pending request — editable
                    Rectangle {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        color: root.pane
                        border.color: root.line
                        border.width: 1
                        visible: intercept.current !== null

                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: 6
                            spacing: 4

                            Text {
                                Layout.fillWidth: true
                                text: intercept.current
                                      ? ("#" + intercept.current.id
                                         + "  " + (intercept.current.tls ? "https" : "http")
                                         + "://" + intercept.current.host
                                         + ":"  + intercept.current.port)
                                      : ""
                                color: root.accent
                                font.family: "Consolas"
                                font.pixelSize: 12
                                elide: Text.ElideRight
                            }

                            ScrollView {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                clip: true
                                TextArea {
                                    id: interceptArea
                                    wrapMode: TextArea.NoWrap
                                    font.family: "Consolas"
                                    font.pixelSize: 12
                                    color: root.text
                                    background: Rectangle { color: "#080808"; border.color: root.line; border.width: 1 }
                                    text: intercept.current ? intercept.current.text : ""
                                }
                            }

                            // Reset the editable area whenever the current
                            // pending changes -- the user-edit binding break
                            // means we can't rely on the original binding to
                            // refresh.
                            Connections {
                                target: intercept
                                function onCurrentChanged() {
                                    interceptArea.text = intercept.current
                                                         ? intercept.current.text
                                                         : ""
                                }
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: 8
                                AccentButton {
                                    label: "Forward →"
                                    onClicked: intercept.forward(interceptArea.text)
                                }
                                AccentButton {
                                    label: "Drop ✕"
                                    onClicked: intercept.drop()
                                }
                                Item { Layout.fillWidth: true }
                                Cell {
                                    text: intercept.queueDepth > 1
                                          ? ((intercept.queueDepth - 1) + " more waiting")
                                          : ""
                                    color: root.dim
                                }
                            }
                        }
                    }

                    // Idle state when no current pending
                    Item {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        visible: intercept.current === null
                        Text {
                            anchors.centerIn: parent
                            text: intercept.enabled
                                  ? "Waiting for the next request to land…"
                                  : "Intercept is off — traffic flows through normally."
                            color: root.dim
                            font.family: "Consolas"
                            font.pixelSize: 13
                        }
                    }
                }
            }
        }

        Rectangle { Layout.fillWidth: true; height: 1; color: root.line }

        // Status bar
        Rectangle {
            color: "#000000"
            Layout.fillWidth: true
            height: 22
            RowLayout {
                anchors.fill: parent
                spacing: 12
                anchors.leftMargin: 6
                Cell {
                    text: "proxy: " + (proxyServer.isRunning ? ("listening on :" + proxyServer.listeningPort) : "stopped")
                    color: proxyServer.isRunning ? root.text : "#ff5050"
                }
                Cell { text: history.count + " requests"; color: root.accent }
                Cell {
                    text: proxyServer.filteredCount > 0
                          ? (proxyServer.filteredCount + " filtered")
                          : ""
                    color: "#a0a0a0"
                }
                Cell {
                    text: "scope: " + (projectStore.inScopeList.length === 0
                                       ? "open"
                                       : projectStore.inScopeList.length + " in")
                          + (projectStore.outOfScopeList.length > 0
                             ? (" / " + projectStore.outOfScopeList.length + " out")
                             : "")
                    color: root.dim
                }
                Cell {
                    text: intercept.enabled
                          ? ("INTERCEPT" + (intercept.queueDepth > 0
                                            ? " (" + intercept.queueDepth + ")"
                                            : ""))
                          : ""
                    color: "#ff5050"
                }
                Item { Layout.fillWidth: true }
                Cell {
                    text: "clear"
                    color: root.accent
                    MouseArea {
                        anchors.fill: parent
                        onClicked: {
                            proxyModel.clear()
                            history.currentIndex = -1
                        }
                    }
                }
            }
        }
    }
}
