######################################################################
# Automatically generated by qmake (3.0) Thu Apr 14 21:13:11 2016
######################################################################

CONFIG -= qt
CONFIG -= core
CONFIG += console

TEMPLATE = app
TARGET = ip8000man
DEPENDPATH += .
INCLUDEPATH += .

unix {
DEFINES += DEBUG
LIBS += -lcurl
}

#fileupload,getinfo

# Input
SOURCES += main.c
