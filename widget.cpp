#include "widget.h"

Widget::Widget(QWidget *parent, int argc, char** argv) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);
    Network* network = new Network();

    bool ok = true;
    QString text;

    if(argc > 1) {
        text = argv[1];
    } else {
        QString devList = network->getInterfaceList();
        text = QInputDialog::getText(this, tr("Info"),tr("Interface list:\n"+devList.toUtf8()+"\n\nInput target interface:"), QLineEdit::Normal, network->getFirstInterface(), &ok); // wlp0s20f3
    }

    if(!ok) {
        parent->close();
    }

    loadUI();

    connect(network, SIGNAL(signalGUI(QVariant)), this, SLOT(addData(const QVariant&)));
    network->startCapture(text);
}

Widget::~Widget()
{
    delete ui;
}

void Widget::loadUI() {
    ui->tableWidget->setColumnCount(11);
    ui->tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget->setHorizontalHeaderLabels(QStringList()
                                               << "No"
                                               << "Type"
                                               << "Source"
                                               << "Destination"
                                               << "Protocol"
                                               << "Source"
                                               << "Destination"
                                               << "len"
                                               << "Source Port"
                                               << "Destination Port"
                                               << "Data");
    ui->tableWidget->horizontalHeader()->setStretchLastSection(true);
}

void Widget::addData(const QVariant &data) {

    QStringList list = data.toStringList();
    int index = list[0].toInt()-1;

    ui->tableWidget->insertRow(index);

    for(int i=0; i<11; i++) {
        QTableWidgetItem* item = new QTableWidgetItem(list[i]);
        ui->tableWidget->setItem(index, i, item);
    }

    printList(list);
    update();
}

void Widget::printList(QStringList list) {
    printf("----------------------------------\n");
    printf("Type:%s\n",             list[1].toUtf8().constData());
    printf("Source:%s\n",           list[2].toUtf8().constData());
    printf("Destination:%s\n",      list[3].toUtf8().constData());
    printf("Protocol:%s\n",         list[4].toUtf8().constData());
    printf("Source:%s\n",           list[5].toUtf8().constData());
    printf("Destination:%s\n",      list[6].toUtf8().constData());
    printf("Len:%s\n",              list[7].toUtf8().constData());
    printf("Source Port:%s\n",      list[8].toUtf8().constData());
    printf("Destination Port:%s\n", list[9].toUtf8().constData());
    printf("Data:%s\n",             list[10].toUtf8().constData());
    printf("----------------------------------\n\n");
}
