#ifndef TRUENAS_PYPWENC_H
#define TRUENAS_PYPWENC_H

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "../pwenc/truenas_pwenc.h"

#define MODULE_NAME "truenas_pypwenc"

/* Module state */
typedef struct {
	PyObject *pwenc_error;
} tnpwenc_module_state_t;

/* Error handling functions */
PyObject *setup_pwenc_exception(void);
const char *pwenc_error_code_to_string(pwenc_resp_t code);
void set_exc_from_pwenc(PyObject *module_ref, pwenc_resp_t code, pwenc_error_t *pwenc_err, const char *additional_info);

#endif