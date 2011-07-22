TARGET = NetworkMonitor
TEMPLATE = app
SOURCES += main.cpp \
    mainwindow.cpp \
    dialogabout.cpp \
    pcapsession.cpp \
    pcapsignal.cpp
HEADERS += mainwindow.h \
    dialogabout.h \
    pcapsession.h \
    pcapsignal.h
FORMS += mainwindow.ui \
    dialogabout.ui



# Uncomment __only__one__ of the following two sections to suit your OS ###

# Windows builds...
#  INCLUDEPATH += c:\WpdPack\Include
#  LIBS += c:\WpdPack\Lib\wpcap.lib
#  LIBS += C:\Qt\2010.02.1\mingw\lib\libws2_32.a

# Linux builds...
  LIBS += -lpcap # Linux
  RESOURCES += icons.qrc
