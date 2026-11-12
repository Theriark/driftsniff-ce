"""The QNAP CGI paths the collector calls and the resources it reads from them.

Every path, parameter and element name is **UNVERIFIED**: QNAP does not publish a reference for
these configuration CGIs. They come from open source clients that read real systems (sources and
dates in docs/vendor-notes/qnap.md); no lab QNAP was used. When a lab result or a vendor document
corrects a name, correct this module and ``normalize.py``; nothing else has to change.

Users, user groups and the network services (SSH, Telnet, SMB, NFS, FTP, myQNAPcloud, UPnP) are
not read: no source names a read-only call for them, and the collector does not guess one.
"""

from typing import Final

LOGIN_PATH: Final = "/cgi-bin/authLogin.cgi"
LOGOUT_PATH: Final = "/cgi-bin/authLogout.cgi"
SYSINFO_PATH: Final = "/cgi-bin/management/manaRequest.cgi?subfunc=sysinfo&hd=no&multicpu=1"
DISK_USAGE_PATH: Final = (
    "/cgi-bin/management/chartReq.cgi?chart_func=disk_usage&disk_select=all&include=all"
)
# The list call of the QNAP Go SDK (notes, statement 9); "reload" re-reads the package list.
APPS_PATH: Final = (
    "/cgi-bin/application/appRequest.cgi?subfunc=qpkg&apply=10&action=reload&lang=eng"
)

# Resource name to the path its document is read from. Two resources share a document; the
# client reads each document once per run. The login page answer needs no session.
RESOURCE_PATHS: Final = {
    "qnap-system": SYSINFO_PATH,
    "qnap-network-interfaces": SYSINFO_PATH,
    "qnap-volumes": DISK_USAGE_PATH,
    "qnap-shared-folders": DISK_USAGE_PATH,
    "qnap-web-services": LOGIN_PATH,
    "qnap-apps": APPS_PATH,
}
RESOURCES: Final = tuple(RESOURCE_PATHS)
NO_SESSION_PATHS: Final = frozenset({LOGIN_PATH})
