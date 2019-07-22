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
private:
    Ui::Widget *ui;
    void loadUI();
    void printList(QStringList list);
public:
    explicit Widget(QWidget *parent = nullptr, int argc = 0, char** argv = nullptr);
    ~Widget();
public slots:
    void addData(const QVariant&);
};

#endif // WIDGET_H
