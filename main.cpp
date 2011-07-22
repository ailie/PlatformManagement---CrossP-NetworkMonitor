#include <QtGui/QApplication>


#include "mainwindow.h"
#include "pcapsession.h"

#include <iostream>


int main(int argc, char *argv[])
{

#ifdef linux
    if (getuid())
    {
        qWarning("ERROR: User not authorized - root only.");
//        return 1;
    }
#endif

    QApplication a(argc,argv);

    MainWindow w;
    w.show();

    return a.exec();

}
