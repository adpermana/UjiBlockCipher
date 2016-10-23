TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.c \
    aes/aes.c \
    awd.c \
    num_utils.c \
    sbox_utils.c \
    stats.c \
    des/des.c \
    pattimura/pattimura.c \
    pattimura/utils.c

HEADERS += \
    aes/aes.h \
    awd.h \
    num_utils.h \
    sbox_utils.h \
    stats.h \
    pattimura/pattimura.h \
    pattimura/utils.h \
    des/des.h

