HANDLER = flickr-handler
DEBUG = y

APXS = apxs

INCLDIR = -I/usr/local/include
LIBDIR = -L/usr/local/lib

LIBS = -lcurl

all: mod_flickr.c md5.h flick.h
	${APXS} -DDEBUG -ci -n ${HANDLER} ${INCLDIR} ${LIBDIR} mod_flickr.c ${LIBS}

clean:
	rm -rf *.o *.lo *.la *.slo

