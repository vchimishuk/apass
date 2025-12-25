PORTNAME=	apass
PORTVERSION=	0.0.1
CATEGORIES=	sysutils

MAINTAINER=	vchimishuk@yandex.ru
COMMENT=	passwords manager with attributes support
WWW=		https://github.com/vchimishuk/apass

LICENSE=	GPLv3+

USES=		cmake
LIB_DEPENDS=	libgcrypt.so:security/libgcrypt

USE_GITHUB=	yes
GH_ACCOUNT=	vchimishuk
GH_PROJECT=	${PORTNAME}
GH_TAGNAME=	786a633

PLIST_FILES=	bin/${PORTNAME} \
		share/man/man1/apass.1.gz

post-install:
	${INSTALL_MAN} ${WRKSRC}/${PORTNAME}.1 ${STAGEDIR}${PREFIX}/share/man/man1

.include <bsd.port.mk>
