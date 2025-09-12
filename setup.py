from setuptools import setup, Extension

truenas_pypwenc_ext = Extension(
    'truenas_pypwenc',
    sources=[
        'src/pypwenc/truenas_pypwenc.c',
        'src/pypwenc/error.c',
        'src/pwenc/pwenc_context.c',
        'src/pwenc/pwenc_open.c',
        'src/pwenc/pwenc_close.c',
        'src/pwenc/pwenc_encrypt.c',
        'src/pwenc/pwenc_decrypt.c',
        'src/pwenc/pwenc_utils.c'
    ],
    include_dirs=['src/pwenc', 'src/pypwenc'],
    libraries=['ssl', 'crypto', 'bsd']
)

setup(
    ext_modules=[truenas_pypwenc_ext]
)