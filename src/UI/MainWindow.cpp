#include "MainWindow.h"

#ifdef FS_HAS_QT
#include <QApplication>
#include <QHeaderView>
#include <QVBoxLayout>
#endif

MainWindow::MainWindow(Logger &logger, RiskCalculator &calculator
#ifdef FS_HAS_QT
                       , QWidget *parent
#endif
                       )
#ifdef FS_HAS_QT
    : QMainWindow(parent), logger(logger), calculator(calculator)
#else
    : logger(logger), calculator(calculator)
#endif
{
#ifdef FS_HAS_QT
    setWindowTitle(QStringLiteral("Форензик-сканер"));
    auto *central = new QWidget(this);
    auto *layout = new QVBoxLayout(central);

    progressBar = new QProgressBar(this);
    progressBar->setRange(0, 100);
    progressBar->setValue(calculator.totalRisk());

    summaryLabel = new QLabel(this);

    tabWidget = new QTabWidget(this);
    hashTree = new QTreeWidget(this);
    browserTree = new QTreeWidget(this);
    discordTree = new QTreeWidget(this);

    QStringList headers;
    headers << "Триггер" << "Источник" << "Совпадение" << "Вес" << "Время";
    hashTree->setHeaderLabels(headers);
    browserTree->setHeaderLabels(headers);
    discordTree->setHeaderLabels(headers);

    tabWidget->addTab(hashTree, QStringLiteral("Хеши"));
    tabWidget->addTab(browserTree, QStringLiteral("Браузер"));
    tabWidget->addTab(discordTree, QStringLiteral("Discord"));

    layout->addWidget(progressBar);
    layout->addWidget(summaryLabel);
    layout->addWidget(tabWidget);
    setCentralWidget(central);

    populateTrees();
    updateSummary();
#endif
}

void MainWindow::showWindow() {
#ifdef FS_HAS_QT
    show();
#else
    (void)logger;
    (void)calculator;
#endif
}

#ifdef FS_HAS_QT

void MainWindow::populateTrees() {
    populateTree(hashTree, logger.getCategory("Хеши"));
    populateTree(browserTree, logger.getCategory("Браузер"));
    populateTree(discordTree, logger.getCategory("Discord"));
}

void MainWindow::populateTree(QTreeWidget *tree, const std::vector<LogEntry> &entries) {
    tree->setColumnCount(5);
    for (const auto &entry : entries) {
        auto *item = new QTreeWidgetItem(tree);
        item->setText(0, QString::fromStdString(entry.triggerType));
        item->setText(1, QString::fromStdString(entry.source));
        item->setText(2, QString::fromStdString(entry.matchedValue));
        item->setText(3, QString::number(entry.weight));
        item->setText(4, QString::fromStdString(entry.timestamp));
    }
    tree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
}

void MainWindow::updateSummary() {
    QString summary = QStringLiteral("Хеши: %1 | Браузер: %2 | Discord: %3 | Риск: %4%")
                          .arg(logger.countCategory("Хеши"))
                          .arg(logger.countCategory("Браузер"))
                          .arg(logger.countCategory("Discord"))
                          .arg(calculator.totalRisk());
    summaryLabel->setText(summary);

    const int risk = calculator.totalRisk();
    QString style = "QProgressBar::chunk { background-color: #4caf50; }";
    if (risk >= 70) {
        style = "QProgressBar::chunk { background-color: #f44336; }";
    } else if (risk >= 30) {
        style = "QProgressBar::chunk { background-color: #ffeb3b; }";
    }
    progressBar->setValue(risk);
    progressBar->setStyleSheet(style);
}

#endif
