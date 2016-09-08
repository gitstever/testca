import M2Crypto
import ctypes
#https://bugzilla.osafoundation.org/show_bug.cgi?id=7530#c13
#https://github.com/M2Crypto/M2Crypto/issues/19
class Ctx(ctypes.Structure):
    _fields_ = [ ('flags', ctypes.c_int),
                 ('issuer_cert', ctypes.c_void_p),
                 ('subject_cert', ctypes.c_void_p),
                 ('subject_req', ctypes.c_void_p),
                 ('crl', ctypes.c_void_p),
                 ('db_meth', ctypes.c_void_p),
                 ('db', ctypes.c_void_p),
                ]

def fix_ctx(m2_ctx, issuer = None):
    ctx = Ctx.from_address(int(m2_ctx))

    ctx.flags = 0
    ctx.subject_cert = None
    ctx.subject_req = None
    ctx.crl = None
    if issuer is None:
        ctx.issuer_cert = None
    else:
        ctx.issuer_cert = int(issuer.x509)


def new_extension(name, value, critical=0, issuer=None, _pyfree = 1):
    """
    Create new X509_Extension instance.
    """
    if name == 'subjectKeyIdentifier' and \
        value.strip('0123456789abcdefABCDEF:') is not '':
        raise ValueError('value must be precomputed hash')

    ctx = M2Crypto.m2.x509v3_set_nconf()
    #ctx not zeroed
    fix_ctx(ctx, issuer)

    x509_ext_ptr = M2Crypto.m2.x509v3_ext_conf(None, ctx, name, value)

    if x509_ext_ptr is None:
        raise Exception
    x509_ext = M2Crypto.X509.X509_Extension(x509_ext_ptr, _pyfree)
    x509_ext.set_critical(critical)
    return x509_ext 
