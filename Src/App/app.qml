import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ApplicationWindow {
    id: root
    visible: true
    width: 1480
    height: 800
    title: "Nullock"
    color: "#0a0a0a"

    readonly property color accent: "#ff8c1a"
    readonly property color text:   "#80f0c0"
    readonly property color rowAlt: "#141414"
    readonly property color rowEven: "#1c1c1c"

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

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 8
        spacing: 6

        Text {
            text: "Nullock — HTTP History"
            color: root.accent
            font.pixelSize: 16
            font.bold: true
        }

        Rectangle {
            color: "#000000"
            Layout.fillWidth: true
            height: 24
            RowLayout {
                anchors.fill: parent
                spacing: 0
                HeaderCell { text: "#";        Layout.preferredWidth: 50 }
                HeaderCell { text: "Host";     Layout.preferredWidth: 280 }
                HeaderCell { text: "Method";   Layout.preferredWidth: 70 }
                HeaderCell { text: "URL";      Layout.fillWidth: true; Layout.minimumWidth: 200 }
                HeaderCell { text: "Status";   Layout.preferredWidth: 60 }
                HeaderCell { text: "MIME";     Layout.preferredWidth: 130 }
                HeaderCell { text: "Params";   Layout.preferredWidth: 60 }
                HeaderCell { text: "TLS";      Layout.preferredWidth: 40 }
                HeaderCell { text: "IP";       Layout.preferredWidth: 130 }
                HeaderCell { text: "Time";     Layout.preferredWidth: 110 }
            }
        }

        ListView {
            id: history
            Layout.fillWidth: true
            Layout.fillHeight: true
            model: proxyModel
            clip: true
            ScrollBar.vertical: ScrollBar {}

            delegate: Rectangle {
                width: history.width
                height: 22
                color: (index % 2 === 0) ? root.rowEven : root.rowAlt
                RowLayout {
                    anchors.fill: parent
                    spacing: 0
                    Cell { text: rowId;                 Layout.preferredWidth: 50 }
                    Cell { text: host;                  Layout.preferredWidth: 280 }
                    Cell { text: method;                Layout.preferredWidth: 70 }
                    Cell { text: url;                   Layout.fillWidth: true; Layout.minimumWidth: 200 }
                    Cell { text: statusCode || "";      Layout.preferredWidth: 60 }
                    Cell { text: mime;                  Layout.preferredWidth: 130 }
                    Cell { text: params > 0 ? params : ""; Layout.preferredWidth: 60 }
                    Cell { text: tls ? "✓" : "";        Layout.preferredWidth: 40; horizontalAlignment: Text.AlignHCenter }
                    Cell { text: ip;                    Layout.preferredWidth: 130 }
                    Cell { text: timestamp;             Layout.preferredWidth: 110 }
                }
            }
        }

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
                Item { Layout.fillWidth: true }
                Cell {
                    text: "clear"
                    color: root.accent
                    MouseArea { anchors.fill: parent; onClicked: proxyModel.clear() }
                }
            }
        }
    }
}
