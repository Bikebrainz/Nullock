#include <QtTest/QtTest>

class TestExample : public QObject {
    Q_OBJECT

private slots:
    void initTestCase() {}
    void cleanupTestCase() {}
    void test_example() {
        QVERIFY(true);
    }
};

QTEST_MAIN(TestExample)
#include "test.moc"
