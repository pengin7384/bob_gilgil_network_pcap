#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <qstring.h>
#include <pcap/pcap.h>
#include <QStringList>
#include <QVariant>
#include <QInputDialog>
#include "ui_widget.h"
#include "network.h"


namespace Ui {

class Widget;
}

class Widget : public QWidget
{
    Q_OBJECT

public:
    explicit Widget(QWidget *parent = nullptr);
    ~Widget();
public slots:
    void addData(const QVariant&);
private:
    Ui::Widget *ui;
    void loadUI();
    void printList(QStringList list);

};

#endif // WIDGET_H
