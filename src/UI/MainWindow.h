#pragma once

#include "Logger.h"
#include "RiskCalculator.h"

#ifdef FS_HAS_QT
#include <QLabel>
#include <QMainWindow>
#include <QProgressBar>
#include <QTabWidget>
#include <QTreeWidget>
#endif

class MainWindow
#ifdef FS_HAS_QT
    : public QMainWindow
#endif
{
public:
#ifdef FS_HAS_QT
    explicit MainWindow(Logger &logger, RiskCalculator &calculator, QWidget *parent = nullptr);
#else
    MainWindow(Logger &logger, RiskCalculator &calculator);
#endif
    void showWindow();

private:
    Logger &logger;
    RiskCalculator &calculator;
#ifdef FS_HAS_QT
    QProgressBar *progressBar = nullptr;
    QLabel *summaryLabel = nullptr;
    QTabWidget *tabWidget = nullptr;
    QTreeWidget *hashTree = nullptr;
    QTreeWidget *browserTree = nullptr;
    QTreeWidget *discordTree = nullptr;

    void populateTrees();
    void populateTree(QTreeWidget *tree, const std::vector<LogEntry> &entries);
    void updateSummary();
#endif
};
