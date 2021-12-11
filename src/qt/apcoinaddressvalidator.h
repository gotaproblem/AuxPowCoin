// Copyright (c) 2011-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef APCOIN_QT_APCOINADDRESSVALIDATOR_H
#define APCOIN_QT_APCOINADDRESSVALIDATOR_H

#include <QValidator>

/** Base58 entry widget validator, checks for valid characters and
 * removes some whitespace.
 */
class ApcoinAddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit ApcoinAddressEntryValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

/** Apcoin address widget validator, checks for a valid apcoin address.
 */
class ApcoinAddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit ApcoinAddressCheckValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

#endif // APCOIN_QT_APCOINADDRESSVALIDATOR_H
