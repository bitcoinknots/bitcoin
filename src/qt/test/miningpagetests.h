// Copyright (c) 2026 The Bitcoin Purity developers
// Distributed under the MIT software license.
#ifndef BITCOIN_QT_TEST_MININGPAGETESTS_H
#define BITCOIN_QT_TEST_MININGPAGETESTS_H

#include <QObject>

class MiningPageTests : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void hashrateBaselineAndFormula();
    void hashrateWindowAndResets();
    void hashrateVisibilityAndHistory();
    void networkHashrateAndChance();
    void hashrateAxisUsesHundreds();
    void bestShareFormatting();
    void summaryLabelsDistinguishSharesAndBlocks();
};

#endif // BITCOIN_QT_TEST_MININGPAGETESTS_H
